I haven’t looked closely at the details of your proposal yet, but I think charging the BAL byte floor on a per-transaction basis could introduce griefing vectors, regardless of how it is implemented. This could potentially be mitigated by exposing the current floor to users via EIP-8141 frame transactions.

However, there is a cleaner approach: at the end of each block, set the block’s resource consumption to max(total_tx_gas_used, total_byte_floor), where total_byte_floor is the sum of the static byte floor and the BAL byte floor derived from the attached BAL list.

This ensures that the block remains properly constrained by total_byte_floor, even if some transactions are undercharged. More importantly, this approach is much less disruptive to UX and significantly simpler to implement.
