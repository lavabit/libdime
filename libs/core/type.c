#include <core/magma.h>

/**
 * Takes a type code and returns the fully enumerated string associated with that type.
 * Is typically used for recording the type code as a string in error messages.
 *
 * @param type The type code to evaluate.
 * @return Null terminated string containing type name. String is stored in static buffer and returned as a pointer.
 */
const char *type(M_TYPE type) {

	switch (type) {

	// Strings
	case (M_TYPE_STRINGER):
		return "M_TYPE_STRINGER";
	case (M_TYPE_NULLER):
		return "M_TYPE_NULLER";
	case (M_TYPE_PLACER):
		return "M_TYPE_PLACER";
	case (M_TYPE_BLOCK):
		return "M_TYPE_BLOCK";

	// Enum
	case (M_TYPE_ENUM):
		return "M_TYPE_ENUM";

	// Multi
	case (M_TYPE_MULTI):
		return "M_TYPE_MULTI";

	// Boolean
	case (M_TYPE_BOOLEAN):
		return "M_TYPE_BOOLEAN";

	// Unsigned integers
	case (M_TYPE_UINT64):
		return "M_TYPE_UINT64";
	case (M_TYPE_UINT32):
		return "M_TYPE_UINT32";
	case (M_TYPE_UINT16):
		return "M_TYPE_UINT16";
	case (M_TYPE_UINT8):
		return "M_TYPE_UINT8";

	// Signed integers
	case (M_TYPE_INT64):
		return "M_TYPE_INT64";
	case (M_TYPE_INT32):
		return "M_TYPE_INT32";
	case (M_TYPE_INT16):
		return "M_TYPE_INT16";
	case (M_TYPE_INT8):
		return "M_TYPE_INT8";

	case (M_TYPE_FLOAT):
		return "M_TYPE_FLOAT";
	case (M_TYPE_DOUBLE):
		return "M_TYPE_DOUBLE";
	case (M_TYPE_EMPTY):
		return "M_TYPE_EMPTY";
	}

	return "";
}
