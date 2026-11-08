# Opaque Token Forensics, Controlled Replay & JSVMP Workflows

> Attribution: Distilled from `WhiteNightShadow/hello_js_reverse_skill@9fb8e001d68a5e0b83f12285950f667f219623a9` (`CC0-1.0`).

## 1. Opaque Token Batch Inspection (`scripts/opaque_token_inspect.py`)

When an application generates opaque query parameters, headers, or body fields (such as custom signatures or anti-bot tokens), collect at least 3–5 samples under controlled input changes before attempting to decompile the full bundle.

### Workflow

1. **Collect Samples:** Extract tokens from HAR captures or runtime traces into a newline-delimited list or pass them directly as positional arguments.
2. **Inspect Shape and Byte Stability:**
   - Run `scripts/opaque_token_inspect.py` with `--encoding auto` (or `base64`, `base64url`, `hex`, `custom --alphabet <64chars>`).
   - Compare `head_stable_positions` and `tail_stable_positions` to separate static magic bytes/version headers from variable payload slices.
   - Check `length_field_candidates` to detect embedded 1/2/4-byte length prefixes.
3. **Cancel Per-Token Single-Byte XOR Masks:**
   - Pass `--xor-align` to align head and tail byte slices across variable-length tokens and recover relative XOR keys without knowing the absolute key.
   - Pass `--checksum crc32 --checksum-at tail --endian little` (or `adler32`) to solve for candidate XOR masks (`checksum_key_candidates`) when the token embeds a self-checking trailer or header.

## 2. Controlled Single-Variable Replay (`scripts/experiment_ledger.py`)

Server acceptance or rejection of a modified request only proves a hypothesis when **exactly one variable** changes between the baseline and candidate requests and all online attempts remain within a pre-declared budget.

### Outcome Taxonomy

| Outcome           | Meaning                                                          | Consumes Online Budget?                                  |
| ----------------- | ---------------------------------------------------------------- | -------------------------------------------------------- |
| `not_sent`        | Blocked locally before transmission                              | No                                                       |
| `transport_error` | Local socket, DNS, or TLS handshake failure before HTTP response | No                                                       |
| `rejected`        | Server returned an application/anti-bot rejection                | Yes (and halts batch unless `--allow-rejections` is set) |
| `accepted`        | Server accepted the request wrapper                              | Yes                                                      |
| `target_ok`       | Full target business response succeeded                          | Yes                                                      |

### Workflow

1. **Audit Before Sending:**
   - Save the baseline request JSON and candidate request JSON.
   - Run `scripts/experiment_ledger.py audit --base <base_json> --candidate <cand_json> --allow header:x-sign --must-change header:x-sign`.
   - Verify `"single_variable_confirmed": true`. Note that `audit` normalizes query parameter order, header casing, and cookie order automatically, and masks all changed values to `{"sha256": "<16-hex>", "length": N}` so raw credentials never leak into logs.
2. **Check Budget Gate:**
   - Run `scripts/experiment_ledger.py gate --ledger <ledger_jsonl> --batch <batch_id> --budget 5`.
   - Only transmit when exit code is `0` (`"allowed": true`).
3. **Record Every Attempt:**
   - Immediately log the outcome via `scripts/experiment_ledger.py record`.

## 3. Portable Bundle Baseline Fixity (`scripts/project_baseline.py`)

Web and Electron targets silently rotate JavaScript bundles or WebAssembly modules between sessions.

1. **Create Baseline:** Run `scripts/project_baseline.py create --root <case_dir> --manifest baseline.json --files <rel_paths...> --identity sdk_public=1.0.0`.
2. **Verify Before Reusing Hooks:** Run `scripts/project_baseline.py check --root <case_dir> --manifest baseline.json`. If `"status": "changed"`, re-verify offsets and AST selectors before trusting cached conclusions.

## 4. JSVMP (JavaScript Virtual Machine Protection) Analysis Playbook

When REA `search_js_bundle` or `trace_js_function` reveals a large switch-dispatch loop operating on a bytecode array and virtual register file:

1. **Locate the Interpreter Loop:** Identify the dispatcher (`while` + `switch` or computed jump table), instruction pointer (`IP`), virtual stack/register array, and constant pool loader.
2. **Log Boundary Operations First:** Instead of reconstructing every arithmetic opcode, hook host boundary calls (`Function.prototype.apply`, `CryptoSubtle`, `XMLHttpRequest.prototype.send`, `fetch`, property getters on `window`/`navigator`/`document`) and log `(ip, reg_snapshot, args, return_value)`.
3. **Identify Crypto Constants:** Search for standard S-boxes, IVs, and magic constants (MD5/SHA-256 initial state words, AES `0x63, 0x7c, 0x77, 0x7b`, CRC32 `0xedb88320`, HMAC `0x36` / `0x5c` XOR pads) inside the VM constant pool.
4. **Cross-Verify via `scripts/opaque_token_inspect.py`:** Feed VM-generated tokens into `scripts/opaque_token_inspect.py` to confirm whether byte length, entropy, and CRC/XOR structure match your reconstructed algorithm offline before running any online replay.
