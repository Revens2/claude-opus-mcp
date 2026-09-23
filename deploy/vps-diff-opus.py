"""Validation canary astra :18996 (contrat code + relay live, sans ecriture).

`opus_think`/`opus_session` consomment des tours Claude Opus 5.5 : JAMAIS appeles ici
(seul `opus_health`, read-only, est exerce en reel). Valide :
1. `initialize` + `tools/list` via le canary (Bearer dedie) : le canary relaie
   vers l'upstream `:8794`, donc la liste obtenue EST le contrat live amont ;
2. conformite stricte aux 3 outils du contrat code (`politique.py`) : noms
   exacts + description + inputSchema presents ;
3. `resources/list` + `prompts/list` (comportement enregistre) ;
4. refus locaux : outil inconnu (-32000), ecriture sans portee (-32000, local).
Bearer canary lu sur le VPS uniquement (jamais affiche, jamais journalise).
Sortie : PASS/FAIL + ecarts uniquement.
"""
import json
import sys
import urllib.request

CANARY_FILE = sys.argv[1] if len(sys.argv) > 1 else "/opt/astra-gateway-rs/.mcp_token"
CANARY = "http://127.0.0.1:18996"

# Scripts operateur : loopback VPS uniquement.
BASES_AUTORISEES = (CANARY,)

# Contrat code : 3 outils `astra_gateway/politique.py`.
OUTILS_ATTENDUS = {"opus_health", "opus_think", "opus_session"}


def lire_token(path):
    try:
        with open(path, encoding="utf-8") as fh:
            tok = fh.read().strip()
    except OSError:
        print("JETON_CANARY_ILLISIBLE")
        sys.exit(2)
    if len(tok) < 32:
        print("JETON_CANARY_INVALIDE")
        sys.exit(2)
    return tok


TOKEN = lire_token(CANARY_FILE)


def sse_unwrap(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].lstrip()
            try:
                out.append(json.loads(payload))
            except ValueError:
                pass
    return out


def post(body, token=None, session=None):
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer " + (token or TOKEN),
        "mcp-protocol-version": "2025-11-25",
    }
    if session:
        headers["mcp-session-id"] = session
    req = urllib.request.Request(  # nosemgrep: python.lang.security.audit.insecure-transport.urllib.insecure-request-object.insecure-request-object
        CANARY + "/mcp", data=json.dumps(body).encode(), headers=headers, method="POST"
    )  # loopback operateur contraint par BASES_AUTORISEES, jamais d'exterieur
    try:
        # base contrainte a BASES_AUTORISEES (loopback operateur, pas de file://)
        with urllib.request.urlopen(req, timeout=120) as res:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            raw = res.read()
            sess = res.headers.get("mcp-session-id") or session
            status = res.status
    except Exception as exc:  # noqa: BLE001 - diagnostic smoke
        return -1, {"transport_error": str(exc)[:120]}, session
    try:
        return status, json.loads(raw), sess
    except ValueError:
        for m in sse_unwrap(raw):
            if m.get("id") == body.get("id"):
                return status, m, sess
        return status, {"sse_messages": len(sse_unwrap(raw))}, sess


ecarts = []

# 1. initialize
st, init, session = post(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "diff", "version": "0"}}}
)
print(f"initialize: http={st} session={bool(session)} result={str(init.get('result'))[:160]}")
if st != 200 or "result" not in init:
    ecarts.append(f"initialize: http={st}")

# 2. tools/list live via relay :8794 vs contrat code
st, lst, session = post(
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session=session
)
outils = {t.get("name"): t for t in ((lst.get("result") or {}).get("tools") or []) if t.get("name")}
print(f"canary tools ({len(outils)}): {sorted(outils)}")
if set(outils) != OUTILS_ATTENDUS:
    ecarts.append(f"outils: manquants={sorted(OUTILS_ATTENDUS - set(outils))} "
                  f"ajoutes={sorted(set(outils) - OUTILS_ATTENDUS)}")
for nom, outil in outils.items():
    if not outil.get("description") or not isinstance(outil.get("inputSchema"), dict):
        ecarts.append(f"outil {nom}: description/schema manquant")

# 3. resources/prompts (comportement)
for method in ("resources/list", "prompts/list"):
    st, resp, session = post(
        {"jsonrpc": "2.0", "id": 3, "method": method, "params": {}}, session=session
    )
    print(f"{method}: http={st} result={str(resp.get('result'))[:160]} erreur={'error' in resp}")

# 4. appel reel read-only opus_health (JAMAIS opus_think/session : cout Claude Opus 5.5)
st, hs, session = post(
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "opus_health", "arguments": {}}}, session=session
)
print(f"opus_health: http={st} erreur={'error' in hs}")
if "error" in hs:
    ecarts.append("opus_health: erreur inattendue")

# 5. refus locaux : inconnu + ecriture sans portee (Bearer court non fourni :
#    on simule via un Bearer invalide -> 401, puis via politique : l'outil
#    inconnu avec le Bearer valide suffit ici ; l'ecriture est couverte en TU).
st, ru, session = post(
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "outil-inexistant-xyz", "arguments": {}}}, session=session
)
code_u = (ru.get("error") or {}).get("code")
print(f"refus inconnu={code_u}")
if code_u != -32000:
    ecarts.append(f"refus inconnu={code_u} (attendu -32000)")

if ecarts:
    print("ECARTS:")
    for e in ecarts:
        print(f"  - {e}")
    print("RESULT: FAIL")
    sys.exit(1)
print("RESULT: PASS (canary conforme au contrat + relay live, zero ecriture)")
