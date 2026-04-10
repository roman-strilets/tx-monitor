"""Deserializers package.

This package is intended to host the deserializer modules that were
previously placed directly under `src/` (for example:
`deserializer_core.py`, `deserializer_kernels.py`, `deserializer_proofs.py`,
`deserializer_tx.py`, and `deserializer.py`).

Move those modules here and update imports to use this package as needed.

The package also exposes the compatibility shim names at package level so
callers can import directly from ``src.deserializers`` instead of the
``deserializer`` submodule.
"""

from src.deserializers.deserializer_core import (
	BufferReader,
	DeserializationError,
	KernelSubtype,
	get_kernel_subtype_name,
	decode_msb_bits,
	decode_lsb_bits,
	decode_utf8,
)
from src.deserializers.deserializer_proofs import (
	deserialize_confidential_range_proof,
	deserialize_public_range_proof,
	deserialize_recovery_asset_proof,
	deserialize_recovery_confidential_range_proof,
	deserialize_recovery_public_range_proof,
	deserialize_asset_proof,
	deserialize_lelantus_proof,
	deserialize_sigma_proof,
)
from src.deserializers.deserializer_kernels import deserialize_kernel
from src.deserializers.deserializer_block import (
	deserialize_body_pack_payload,
	deserialize_body_payload,
	deserialize_header_pack,
	deserialize_new_tip_payload,
)
from src.deserializers.deserializer_tx import (
	deserialize_new_transaction_payload,
	deserialize_transaction,
	deserialize_input,
	deserialize_output,
)

__all__ = [
	"BufferReader",
	"DeserializationError",
	"KernelSubtype",
	"get_kernel_subtype_name",
	"decode_msb_bits",
	"decode_lsb_bits",
	"decode_utf8",
	"deserialize_confidential_range_proof",
	"deserialize_public_range_proof",
	"deserialize_recovery_asset_proof",
	"deserialize_recovery_confidential_range_proof",
	"deserialize_recovery_public_range_proof",
	"deserialize_asset_proof",
	"deserialize_lelantus_proof",
	"deserialize_sigma_proof",
	"deserialize_kernel",
	"deserialize_body_pack_payload",
	"deserialize_body_payload",
	"deserialize_header_pack",
	"deserialize_new_tip_payload",
	"deserialize_new_transaction_payload",
	"deserialize_transaction",
	"deserialize_input",
	"deserialize_output",
]
