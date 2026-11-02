# Patch Report: Fix Worker Panic on Closed Report Channel (#883)

## Executive Summary
- **Target Repository**: [`hatoo/oha`](https://github.com/hatoo/oha)
- **Target Issue**: [#883](https://github.com/hatoo/oha/issues/883) — *Panic: Unwrapping send on closed report channel causes ReceiveClosed in worker tasks under load*
- **Affected Subsystems**: `src/client.rs`, `src/client_h3.rs`
- **Severity**: High (unhandled worker panic causing premature process abortion under heavy load or early parent termination)
- **Status**: Verified and Patched

---

## Vulnerability & Defect Details

### Symptom
When executing `oha` under high concurrency (e.g. `-n 5000 -c 1000`) or with early termination / latency correction, background worker tasks panicking with:
```text
panic at src/client.rs: called `Result::unwrap()` on an `Err` value: ReceiveClosed
```

### Root Cause Analysis
In `src/client.rs` and `src/client_h3.rs`, worker threads communicate request results back to the aggregator/reporter task using bounded/unbounded `kanal` channels (`report_tx: kanal::Sender<Result<RequestResult, ClientError>>`). 

Every worker loop unconditionally unwrapped the send result:
```rust
report_tx.send(res).unwrap();
```
When the receiver task terminates early (due to test deadline, cancelled signal, or receiver queue shutdown), subsequent send operations fail with `ReceiveClosed`. Because of `.unwrap()`, worker tasks panicked rather than terminating gracefully.

---

## Fix Implementation

1. **Graceful Worker Termination in `src/client.rs`**:
   - Replaced unconditional `.unwrap()` in all worker loops with error-checking.
   - If `report_tx.send(...)` returns an error, workers now break out of the loop and terminate immediately:
     ```rust
     if report_tx.send(res).is_err() || is_cancel {
         break;
     }
     ```
   - In `work_http2_once` and `work_http3_once`, channel closure is treated as cancellation:
     ```rust
     let is_closed = report_tx.send(res).is_err();
     (is_cancel || is_closed, is_reconnect)
     ```
   - In error-forwarding branches, `if report_tx.send(Err(err)).is_err() { return; }` prevents panicking when reporting initial connection failures.
   - In `fast` module, `let _ = report_tx.send(...)` discards send errors when reporting batch results after receiver teardown.

2. **HTTP/3 Parity in `src/client_h3.rs`**:
   - Audited and updated all 6 instances of `report_tx.send(...).unwrap()` to guarantee identical crash-free semantics for HTTP/3 connections.

3. **Regression Test**:
   - Added unit test `test_work_does_not_panic_on_closed_receiver` in `src/client.rs`.
   - The test instantiates a client, immediately drops the channel receiver (`drop(rx)`), and executes `work(...)`. It confirms workers terminate cleanly without panicking.

---

## Verification & Quality Assurance

- **Unit Test Suite**: 42 passed, 0 failed.
  ```text
  test client::tests::test_work_does_not_panic_on_closed_receiver ... ok
  test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.05s
  ```
- **Linter Check**: `cargo clippy -- -D warnings` passed with 0 warnings.
- **Git Branch**: `fix/issue-883-worker-panic`
