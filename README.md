# claude-opus-gateway-rs — facade Rust devant l'upstream Python fige

Miroir de `astra_gateway` Python : validation Bearer + politique explicite
1 lecture / 2 ecritures / 0 admin + proxy vers `astra_mcp` (`:8794`,
loopback, sans auth — isolation systemd, `x-astra-gw-acteur` injecte apres
authentification). Metier conserve : delegation Claude Opus 5.5 + OAuth Python.

## Contrat conserve

`initialize`/sessions passthrough, `tools/list` filtree par portees (1 en
lecture, 3 en lecture+ecriture), `tools/call` avec refus local AVANT envoi,
`resources/list` + `prompts/list` verbatim.

## Differences assumees (contrat outils intact)

401 au format framework (URL PRM exacte presente), PRM sans
`bearer_methods_supported`, metadata AS format framework (`none` seul) servie
a la racine (suffixe 404 comme le Python), rewrite version, ajout `/ready`,
semantique framework ecriture⊇lecture (inatteignable : middleware exige la
lecture).

## Environnement (`OPUS_GW_RS_*`)

| Variable | Defaut | Role |
|---|---|---|
| `OPUS_GW_RS_ISSUER` | issuer prod | HTTPS requis |
| `OPUS_GW_RS_UPSTREAM` | `http://127.0.0.1:8794` | loopback requis |
| `OPUS_GW_RS_PORT` | `18996` (canary) | `8796` a la bascule (GATEE) |
| `OPUS_GW_RS_TOKEN` / `_TOKEN_FILE` | `/opt/astra-gateway-rs/.mcp_token` | Bearer dedie >= 32, fail-closed |
| `OPUS_GW_RS_TOKEN_SCOPES` | lecture+ecriture | quoté dans l'unit (lecon lot 2) |
| `OPUS_GW_RS_CONSENT_HASH` | vide (= refuse) | PBKDF2 consentement |

## Preuves lot astra (passerelle)

- `cargo fmt --check` 0, `cargo clippy --all-targets -- -D warnings` 0.
- `cargo test` : politique 1/2, visibles 1/3, 401, health/PRM, acteur+mode
  injectes, refus locaux.
- Canary VPS `:18996` + validation vs `:8796` : voir `progress.md`.
- Bascule `:8796` GATEE (OAuth JWT meme famille + delegation Claude Opus 5.5 —
  prudence metier + exploitant) : aucune prod astra existante (cutover 15/09).
