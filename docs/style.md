#Programming Style

## General Principles

### Character Encoding

Code should use only the characters in the ASCII character set defined by
RFC20.

#### *Exception*

Locale-specific customization is free to use any appropriate character set.

### Line Length/Text Width

The maximum length of any one line shall be 80 characters.

#### *Exception*

String constants may break this rule so that any substring may be
searched for without worrying whether the substring is split across
multiple lines.

#### Example

```C
void
usage (void)
{
	printf("Usage: program [--verbose] [--format] -i <input files> -o <output files>\n");
}
```

### Tabs and Spaces

Tabs are used for indentation. Spaces are used for column alignment.

### Indentation

Each level of indentation shall add one tab to the previous level.

### Column Alignment

Column alignment refers to aligning rows of text on column boundaries.
It is used when describing the formatting of groups
of items like parameter lists or local variables.

### Example

```C
int32_t       gCount = 0;
unsigned char *gBuf  = NULL;
int64_t       gSize  = 0;

void
function (
	unsigned char *inBuf,
	size_t        inSize,
	unsigned char *outBuf,
	size_t        outSize)
{
	int32_t       i    = 0;
	size_t        sIn  = 0;
	size_t        sOut = 0;
	unsigned char *tmp = NULL;

	...
}
```

## Formatting

### Operator Spacing

Spaces should always be placed on either side of an operator, unless the
operator is the last character in a line.

### Parenthesis

Parenthesis shall be used to explicitly define order of operations
unless all operators share the same order of precedence.

### Constants

Always use 'L' in place of 'l' when defining *long* constants. Do not begin decimal integer constants with '0'.

### Symbolic Constants

C has several mechanisms for creating named, symbolic constants: 

* const-qualified objects
* enumeration constants
* macro definitions

Each of these mechanisms has associated advantages and disadvantages.

Objects that are *const-qualified* have scope and type and so can be
type-checked by the compiler. Because they 
are named objects (unlike macro definitions), some debugging tools can show the name of the object.
The object also consumes memory.

```C
const int32_t max_len = 25;    // const-qualified object
```

Unfortunately, const-qualified objects cannot be used where compile-time integer constants are 
required, namely to define the

* Size of a bit-field member of a structure.
* Size of an array (except in the case of variable length arrays).
* Value of an enumeration constant.
* Value of a case constant.

If any compile-time values are required, an integer constant (an rvalue) must be used.

*Enumeration constants* can be used to represent an integer constant expression that has an integer value.
Unlike const-qualified objects, enumeration constants do not consume memory. No storage is allocated for 
the value, so it is not possible to take the address of an enumeration constant.

A preprocessor directive of the form

<pre>
#define <i>identifier</i> <i>replacement-list</i>
</pre>

defines an object-like *macro definition*. Each subsequent instance of the macro name is replaced by the *replacement-list*.

C programmers frequently define symbolic constants as macro definitions. For example, the code

```C
#define buffer_size (256)
```

defines `buffer_size` as a macro definition whose replacement-list is `(256)`. The preprocessor 
substitutes macro definitions before the compiler does any other symbol processing. Later compilation 
phases never see macro definition symbols, such as `buffer_size`; they see only the replacement-list text after 
macro substitution. As a result, many compilers do not preserve macro names among the symbols they pass on to their debuggers.

Macro names do not observe the scope rules that apply to other names, and may substitute in unanticipated places with unexpected results.

Object-like macros do not consume memory so it is not possible to create a pointer to one.
Macros do not provide for type checking because they are textually replaced by the preprocessor.

### Preprocessor Macro formatting

Macro definition statements shall have one space between the `#define` and the
identifier. The identifier and replacement-list shall be column
aligned if more than one macro definition appear in sequence. For replacement-lists which consist of a single char or
numerical expression, the replacement-list shall be enclosed in
parenthesis. For replacement-lists which span multiple lines, align the
`\`s in the column after one space is added to the longest line in the
replacement-list. Wrap all multiline preprocessor macros in a `do { } while (0)`
statement.

Prefer inline functions or static functions to preprocessor macros defining statements. Such macros are dangerous 
because their use resembles that of real functions, but they have different semantics.
Always avoid side effects in preprocessor macros which may evaluate arguments more than once or not at all.

*CAUTION:* Do not end preprocessor macros with a semicolon. 
Never use preprocessor directives in invocations of preprocessor macros.
 
#### Example

```C
#define MAX_SIZE       (256)
#define MODULE_NAME    "stdio"
#define PRINT_ARRAY(x) do {                                             \
		                   int32_t i = 0;                               \
			               for (i = 0; i < sizeof(x)/sizeof(x[0]); i++) \
				           {                                            \
					           printf("%s\n", x[i]);                    \
						   }                                            \
					   } while (0)
```

#### Example of macro argument semantics

In this example code fragment, note that `i` is incremented three times. Replacing the macro `CUBE`
with an inline function would restore normal function argument semantics.

```C
#define CUBE(X) ((X) * (X) * (X))

	...
	int a = 81 / CUBE(++i);
```

### Enumeration, Structure, and Union Definitions

All enumerations, structures, and unions shall be defined with file or
global scope and shall use the `typedef` storage specifier. The
`typedef`, `enum` or `struct` or `union`, and tag shall be placed on the
same line, with the opening brace on the following line. Members and
enumeration constants shall be listed on their own lines, one
indentation level in from the enum/structure/union braces. Member types
and names shall be column aligned in structures and unions, while
enumeration constant names, equals signs, and their values shall be
column aligned and include a comma after the last enumeration constant.

#### Example

```C
typedef struct myStruct
{
	uint32_t member1;
	int64_t  member2;
} MyStruct;

typedef union myUnion
{
	uint64_t   member1;
	unsigned char   member2;
} myUnion;

typedef enum color
{
	BLUE    = 1,
	GREEN   = 2,
	RED     = 3,
} Color;
```

### C99 Flexible Array Members

As a special case, the last element of a structure with more than one named member may have
an incomplete array type; this is called a flexible array member. In most situations, the flexible 
array member is ignored. In particular, the size of the structure is as if the flexible array
member were omitted except that it may have more trailing padding than the omission would imply.
However, when a . (or ->) operator has a left operand that is (a pointer to) a structure with 
a flexible array member and the right operand names that member, it behaves as if that member 
were replaced with the longest array (with the same element type) that would not make the structure
larger than the object being accessed; the offset of the array shall remain that of the flexible 
array member, even if this would differ from that of the replacement array. If this array would 
have no elements, it behaves as if it had one element but the behavior is undefined if any attempt
is made to access that element or to generate a pointer one past it.

Structures with a flexible array member can be used to produce code with defined behavior.
However, some restrictions apply:

* The incomplete array type must be the last element within the structure.
* There cannot be an array of structures that contain a flexible array member.
* Structures that contain a flexible array member cannot be used as a member of another structure except as the last element of that structure.
* The structure must contain at least one named member in addition to the flexible array member.

### Example

```C
#include <stdlib.h>
 
struct flex_array_struct
{
  int32_t num;
  int32_t data[];
};
 
void 
func (size_t array_size) 
{
	// Space is allocated for the struct

	struct flex_array_struct *structp = (struct flex_array_struct *) malloc(sizeof(struct flex_array_struct) 
         + sizeof(int) * array_size);

	if (structP == NULL) {
		// Handle malloc failure
	}
 
	structp->num = array_size;
 
	/*
	 * Access data[] as if it had been allocated
	 * as data[array_size].
	 */

	for (size_t i = 0; i < array_size; ++i) {
		structp->data[i] = 1;
	}

	return;
}
```

### C99 Integer types

Prefer the **C99** types, defined in `<stdint.h>`

C99 type | replaces | stored as
---- | ---- | ----
int8_t | signed char | signed 8-bit
uint8_t | unsigned char | unsigned 8-bit
int16_t | short | signed 16-bit
uint16_t | unsigned short | unsigned 16-bit
int32_t | int | signed 32-bit
uint32_t | unsigned int | unsigned 32-bit
int64_t | long | signed 64-bit
uint64_t | unsigned long | unsigned 64-bit


### Variable Declarations

A variable declaration shall consist of a storage-class specifier, an optional qualification, and a type specifier.

The storage-class specifiers are:

-   `auto`
-   `extern`
-   `register`
-   `static`
-   `typedef`

The auto storage-class specifier is optional.

The optional qualification is one of:

-   `const`
-   `const volatile`
-   `volatile`

Prefer the C99-style integer types (uint64_t, etc.).

`char` and an implied `int` shall not be used. Use `unsigned char` for `char`.

The storage-class, qualification, and type specifier will collectively
be referred to as a variable’s type.

*CAUTION:* The C Standard limits identifier length to 63 significant initial characters
in an internal identifier or a macro name, and 31 significant initial characters in an external 
identifier. Even if the compiler accepts a larger number of significant characters, do not
exceed these limits.

*CAUTION:* Avoid creating typedefs of pointer types. It makes writing *const-correct* code difficult
as the `const` qualifier will be applied to the pointer type and not the underlying declared type.

*CAUTION:* As late as 2008, in (Volatiles Are Miscompiled, and What to Do about It)[http://dl.acm.org/citation.cfm?id=1450058.1450093], 
all tested compilers generated some percentage of incorrect compiled code with regard to volatile accesses. Therefore, it 
is necessary to know how your compiler behaves when the standard volatile behavior is required.

Eide and Regehr tested a workaround by wrapping volatile accesses with function calls. They describe it with the 
intuition that "we can replace an action that compilers empirically get wrong by a different action—a function
call—that compilers can get right". An example of this workaround is:

```C
int32_t
vol_read_int (volatile int32_t *vp) {
  return *vp;
}

volatile int32_t 
*vol_id_int (volatile int32_t *vp) {
  return vp;
}

const volatile int32_t x;
volatile int32_t y;

void 
foo (void) {
  for (*vol_id_int(&y) = 0; vol_read_int(&y) < 10; *vol_id_int(&y) = vol_read_int(&y) + 1) {
    int32_t z = vol_read_int(&x);
  }

  return;
}
```

#### Example Declarations

```C
extern int64_t size;

typedef struct memoryblock
{
	unsigned int size;
	signed long  length;
	void         *data;
} memoryblock_t;

typedef enum
{
	BLUE  = 1,
	GREEN = 2,
	RED   = 3,
} color_t;

void
function(void)
{
	unsigned char      c           = 0;
	int16_t            s           = 0;
	register uint32_t  i           = 0;
	int64_t            l           = 0L;
	static const float f           = 0.0F;
	volatile double    d           = 0.0F;
	static long double ld          = 0.0F;
	unsigned char      *pC         = NULL;
	uint32_t           aScores[10] = { 0 };

	...
}
```

### Scope

Declarations of objects should be placed so as to minimize 

### Global Variables

Global variables shall have no indentation and will use a single space
to separate the type, name, equals sign, and the initialization value.
If multiple global variables exist in the same file then the variable
types, names, equals signs, and initialization values shall be column
aligned.

### Local Variables

Local function variables shall be placed one indentation level in
from the function declaration. The variable types, names, equals signs, and
initilization values shall be column aligned. If only one local
variable exists then a single space may be used to separate the variable
type, variable name, and equals sign.

All types shall be initialized to a meaningful value. If no meaningful value exists yet
then they shall be initialized according to the following rules. 
* integer types shall be initialized to `0` and `0L` for `long` types
* floating types shall be initialized to `0.0F`
* char types shall be initialized to `0`
* pointer types shall be initialized to `NULL`
* all array types shall be initialized to `{ 0 }`
* enumeration types shall be initialized to `0`
* structure types and union types shall be uninitialized

Array initialization lists shall include a space after
the opening brace, after each comma, and a space before the closing
brace. If an initialization list extends past the text width then it
shall be broken into segments of 5 elements per line, with the first
five being listed on the same line as the variable name and each
following line of elements aligned with the elements above it.

#### Example

```C
/**
 * @brief	Get a cached copy of a static web page.
 * @param	location	a pointer to a managed string containing the location of the requested resource.
 * @return	NULL on failure, or a pointer to an http content object with the contents of the requested resource on success.
 */
http_content_t *
http_get_static (stringer_t *location)
{
	multi_t key = { .type = M_TYPE_STRINGER, .val.st = location };

	if (!content.pages) {
		return NULL;
	}

	return inx_find(content.pages, key);
}
```

### Pointers

Pointers shall have no space between the `*` or `&` and the
variable name during declaration/definition.

#### *Exception*

Declarations of functions returning pointers shall have a space between the `*` and the function name.

#### Example

```C
void * my_alloc(uint_16 size);

int32_t *
function(void)
{
	unsigned char *buf    = NULL;
	unsigned char c       = 0;
	unsigned char *tmp    = NULL;
	int32_t       *result = NULL;

	...

	c = *buf;
	tmp = &c;

	...
	return result;
}
```

### Function Definitions and Prototypes

A function prototype or definition shall not be indented, excluding the
parameter list as decribed below. It shall be formatted such that the
return type is placed first, then the function name on a new line, and
then the parameters. One space shall separate the function name from the opening parenthesis 
of the parameter list. Parameters shall go on the same line
as the function name unless they will extend past the text width or
there are more than three parameters. In these two cases the opening
parenthesis of the parameter list shall go on the same line as the
function name and the parameter list shall begin on the following line.
The parameter list shall be indented by one tab and have the parameter
types and names column aligned. Parameters which fit on the same line
as the function name shall have 1 space following each `,` character
which separates the parameters. If a function takes no parameters then
use `void` as the parameter list.

Function braces shall be placed as follows.
The opening brace shall be placed one line after the parameter list closing parenthesis, at
the same indentation level as the function declaration. 
The closing function brace shall be placed one line after the last
statement in the function, at the same indentation level as the function declaration.

#### Example

```C
/**
 * @brief	Set the domain name and reverse lookup status of a connection.
 * @note	Possible values for status include REVERSE_ERROR, REVERSE_EMPTY, REVERSE_PENDING, and REVERSE_COMPLETE.
 * @param	domain	the new value of the connection's hostname.
 * @param	status	the new value of the connection's reverse lookup status.
 * @return	This function returns no value.
 */
void
con_reverse_domain (connection_t *con, stringer_t *domain, int32_t status) 
{

	mutex_lock(&(con->lock));
	con->network.reverse.status = status;
	con->network.reverse.domain = domain;
	mutex_unlock(&(con->lock));

	return;
}
```

## Executable Code

### Function Calls

A function call shall be placed at the current indentation level 
one line with all arguments separated by a comma and a single
space. If the argumnts extend past the text width, the first
shall go on the function invocation line and all following arguments shall be placed on
their own lines and indented one tab from the function invacation. The terminating
parenthesis and semi-colon shall be placed on the same line and
immediately after the final argument. When parameters are spread across
multiple lines, no space shall follow the separating comma.

#### Example

```C
int32_t
function(void)
{
	...

	otherFunction(var1, 5, NULL);

	var2 = thisFunction(buf,
		bufLen,
		outBuf,
		outLen);

	reallyLongFunctionName(superLongParameterName1,
		superLongParameterName2,
		superLongParameterName3);

	...
}
```

### If, Else If, and Else Statements

If statements shall have a space separating the `if` and the opening
parenthesis of the conditional statement. Braces shall always be used to
contain the statements being executed for the condition, even if only
one statement exists.  The conditional
statement shall not have space between itself and the encapsulating
parenthesis. If a constant is used in the comparison then it shall be
placed on the left side of the comparison.

When multiple conditional statements are used, the first will go on the
same line as the `if`, with all following conditional statements on
their own lines following the first, indented one level.
Each conditional statement will be contained
in a set of parenthesis. The operators which link separate conditional
statements will be placed at the end of the line, with one space
separating the closing parenthesis of the conditional statement and the
logical operator. If conditional statements need to be nested (e.g.
(arg1 && arg2) || (arg3 && arg4)) then each distinct group shall be
formatted as described above with the operator comparing the two groups
going on its own line. Conditional statements shall only be nested once.

`else if` and `else` statements shall be placed on their own line at the
same indentation level as the `if` statement which they follow.

#### Example

```C
bool_t 
chr_punctuation (uchr_t c) 
{
	if ((c >= '!' && c <= '/') || 
		(c >= ':' && c <= '@') || 
		(c >= '[' && c <= '`') || 
		(c >= '{' && c <= '~')) {
		return true;
	}

	return false;
}
```

#### Example

```C
/*
 * Misleading style: is this meant to be assignment, or simply a compare?
 */
if (a = b) {
	...
}

/*
 * Intentional style: it is clear assignment is intended.
 */
if ((a = b) != 0) {
  /* ... */
}
```

### Switch Statements

Switch statements shall have a space separating the `switch` and the
opening parenthesis which encloses the object being switched on. Braces
enclosing the case statements shall be placed on their own lines at the
same indentation level as the `switch`. The `case`s shall be placed on
their own lines and aligned at the same indentation level as the
`switch` with no space between the constant-expression and the colon.
The statements being executed for the space shall be indented by one
level. Braces shall not be used to contain the statements to be executed
for a given case. The default case shall be listed last and contain a
break statement. Whenever the same set of statements is to be executed
for multiple cases, each case shall be placed on its own line with a
comment of the form, `/* Fallthrough */`, placed on its own line
immediately preceding the first case in the group. Cases shall be listed
in alphanumeric order when possible.

### Example

```C
int32_t 
function (void) 
{
	...

	switch (input) {
	case 'a':
		options |= OPTION_ALL;
		break;
	case 'r':
		options |= OPTION_RECURSIVE;
		break;
	case 'V':    // fallthrough
	case 'v':
		options |= OPTION_VERBOSE;
		break;
	case default:
		break;
	}

    ...
}
```

### Loop Statements

For loops shall have a space separating the `for` and the opening
parenthesis of the control expressions. Control statements shall have a
space after each semi-colon and no space between the expressions and
their enclosing parenthesis. If the control expressions extend beyond
the text-width then each expression shall be placed on its own line,
except for the first which shall be placed on the same line as the
`for`. The separating semi-colons shall be placed on the same line as
the control expressions which they terminate. If multiple statements
exist in a single control expression, a space shall follow the comma
which separates them. Braces containing the iteration statements are
required and shall be placed on their own lines at the same indentation
level at the `for`.

Do-while loops shall have the `do` placed on its own line and braces,
which are required, shall have the opening brace placed on its own line
immediately following the `do`. The terminating brace shall be placed on
the line immediately following the last iteration statement. The `while`
will be placed on the same line as the terminating brace with a single
space on either side of the `while` keyword, followed by the control
statement placed in parenthesis and finally the semi-colon terminating
the do-while loop.

While loops shall have a space between the `while` and the opening
parenthesis of the control expression. The opening brace shall be placed
on its own line immediately following the line containing the `while`
and be placed at the same indentation level of the `while`. The closing
brace shall be placed on its own line immediately following the last
iteration statement.

Iteration statements shall be placed at one indentation level in from
the loop statement. Control statements for do-while and while loops
should be formatted the same way as `if` statements.

#### Example

```C
uint32_t 
function (void) 
{
	uint32_t i;

	for (i = 0; i < 5; i++) {
		...
	}

	do {
		...
	} while (i < 5);

	while (i < 5) {
		...
	}

	...
}
```

### Return Statements

Functions shall have at least one return
statement. Additional return statements may be used only in error handling.
The return value shall be wrapped in parenthesis unless
the return value is a constant expression or a variable name.

#### Example

```C
uint32_t 
pool_get_timeout (pool_t *pool) 
{
	if (!pool)
		return 0;

	return pool->timeout;
}
```

### Goto and Label Statements

`goto`s and `label`s shall not be used.

*what about error handling?*

### Preprocessor Directives

Preprocessor directives shall not be indented and their contents shall
be indented according to the code that precedes it. Nested preprocessor
directives shall indent by one level for each nesting. Each `#endif`
shall include a comment on the same line which specifies which `#if` it
is matched with.

#### Example

```C
#ifdef WINDOWS
	#define DPRINTF(x)  OutputDebugString(x)
#else
	#define DPRINTF(x)  perror(x)
#endif // WINDOWS

uint32_t 
function (char *buf, int len) 
{
	if (0 == count) {
		#ifdef WINDOWS
			OutputDebugString(L"Count was 0\n");
		#elif defined LINUX
			perror("Count was 0\n");
		#endif // WINDOWS
	}

	return 0
}
```
## File Level Organization

### Files

Each source code file shall consist of the following groups, in this order:

- File comment
- Header guard
- `#include` statements
- `#define` statements
- `enum`, `struct`, and `union` definitions
- Type declarations
- Function prototypes
- Function definitions

When no order is provided, `#include` statements shall be listed in
alphabetical order and listed in two groups, separated by a blank line:
systems headers and local headers. `#define` statements shall be grouped
according to their use, where each group is preceded by a comment
describing their purpose. Extra comments to further clarify an
individual statement will be placed on their own line immediately
preceding the statement they describe.

### Header Guard

Each header file shall include a header guard to prevent multiple
inclusion.

#### Example

```C
#ifndef MY_HEADER_H
#define MY_HEADER_H

...

#endif // MY_HEADER_H
```

Include statements shall have one space between the `#include` and the
header name being included. They shall be placed in two groups,
separated by a blank line: system headers and local header. When
possible, they should be sorted alphabetically.

#### Example

```C
#include <stdio.h>
#include <sys/stat.h>

#include "common.h"
#include "sorting.h"
```

### Define statements

Define statements shall have on space between the `#define` and the
identifier. The identifier and replacement-list shall be column
aligned. For replacement-lists which only consist of a single char,
integer, or float value, the replacement-list shall be enclosed in
parenthesis. For replacement-lists which span multiple lines, align the
`\`s at the column after one space is added to the longest line in the
replacement-list.

#### Example

```C
#define MAX_SIZE       (256)
#define MODULE_NAME    "stdio"
#define PRINT_ARRAY(x) do                                               \
	                   {                                                \
	                       int32_t i = 0;                               \
	                       for (i = 0; i < sizeof(x)/sizeof(x[0]); i++) \
	                       {                                            \
	                           printf("%s\n", x[i]);                    \
	                       }                                            \
	                   } while (0)
```

### Enumeration, Structure, and Union Definitions

All enumerations, structures, and unions shall be defined with file or
global scope and shall use the `typedef` storage specifier. The
`typedef`, `enum` or `struct` or `union`, and tag shall be placed on the
same line, with the opening brace on the following line. Members and
enumeration constants shall be listed on their own lines, one
indentation level in from the enum/structure/union braces. Member types
and names shall be column aligned in structures and unions, while
enumeration constant names, equals signs, and their values shall be
column aligned and include a comma after the last enumeration constant.

#### Example

```C
typedef struct myStruct
{
	uint32_t member1;
	int64_t  member2;
} MyStruct;

typedef union myUnion
{
	uint64_t      member1;
	unsigned char member2;
} myUnion;

typedef enum color
{
	BLUE    = 1,
	GREEN   = 2,
	RED     = 3,
} Color;
```

### C99 Integer types

Prefer the **C99** types, defined in `<stdint.h>`

int8_t | signed 8-bit
uint8_t | unsigned 8-bit
int16_t |  signed 16-bit
uint16_t | unsigned 16-bit
int32_t | signed 32-bit
uint32_t | unsigned 32-bit
int64_t | signed 64-bit
uint64_t | unsigned 64-bit


### Variable Declarations

A variable declaration shall consist of the following, in order and
separated by a single space:

The storage-class specifier shall be stated, one of:

-   `auto`
-   `extern`
-   `register`
-   `static`
-   `typedef`

If auto storage-class specifier is optional.

The optional qualification is one of:

-   `const`
-   `const volatile`
-   `volatile`

The type specifier shall prefer C99-style integer types (uint64_t etc.).

`char` and an implied `int` shall not be used.

The storage-class, qualification, and type specifier will collectively
be referred to as a variable’s type.

#### Example

```C
extern int64_t size;

typedef struct memoryBlock
{
	uint32_t size;
	int64_t  length;
	void     *data;
} MemoryBlock;

typedef enum
{
	BLUE  = 1,
	GREEN = 2,
	RED   = 3,
} Color;

void
function (void)
{
	unsigned char      c           = 0;
	short              s           = 0;
	register uint32_t  i           = 0;
	int64_t            l           = 0L;
	static const float f           = 0.0F;
	volatile double    d           = 0.0F;
	static long double ld          = 0.0F;
	unsigned char      *pC         = NULL;
	uint32_t           aScores[10] = { 0 };

	...
}
```

### Function Definitions and Prototypes

A function prototype or definition shall not be indented, excluding the
parameter list as decribed below. It shall be formatted such that the
return type is placed first, then the function name on a new line, and
then the parameters. One space shall separate the function name from the opening parenthesis 
of the parameter list. Parameters shall go on the same line
as the function name unless they will extend past the text width or
there are more than three parameters. In these two cases the opening
parenthesis of the parameter list shall go on the same line as the
function name and the parameter list shall begin on the following line.
The parameter list shall be indented by one tab and have the parameter
types and names column aligned. Parameters which fit on the same line
as the function name shall have 1 space following each `,` character
which separates the parameters. If a function takes no parameters then
use `void` as the parameter list.

Function braces shall be placed as follows.
The opening brace shall be placed one line after the parameter list closing parenthesis, at
the same indentation level as the function declaration. 
The closing function brace shall be placed one line after the last
statement in the function, at the same indentation level as the function declaration.

#### Example

```C
/**
 * @brief   Set the domain name and reverse lookup status of a connection.
 * @note    Possible values for status include REVERSE_ERROR, REVERSE_EMPTY,
 *          REVERSE_PENDING, and REVERSE_COMPLETE.
 * @param   domain: the new value of the connection's hostname.
 * @param   status: the new value of the connection's reverse lookup status.
 * @return  This function returns no value.
 */
void
con_reverse_domain (connection_t *con, stringer_t *domain, int32_t status) 
{

	mutex_lock(&(con->lock));
	con->network.reverse.status = status;
	con->network.reverse.domain = domain;
	mutex_unlock(&(con->lock));

	return;
}
```

### Global Variables

Global variables shall have no indentation and will use a single space
to separate the type, name, equals sign, and the initialization value.
If multiple global variables exist in the same file then the variable
types, names, equals signs, and initialization values shall be column
aligned.

### Local Variables

Local function variables shall be placed one indentation level in
from the function declaration. The variable types, names, equals signs, and
initilization values shall be column aligned. If only one local
variable exists then a single space may be used to separate the variable
type, variable name, and equals sign.

All types shall be initialized to a meaningful value. If no meaningful value exists yet
then they shall be initialized according to the following rules. 
* integer types shall be initialized to `0` and `0L` for `long` types
* floating types shall be initialized to `0.0F`
* char types shall be initialized to `0`
* pointer types shall be initialized to `NULL`
* all array types shall be initialized to `{ 0 }`
* enumeration types shall be initialized to `0`
* structure types and union types shall be uninitialized

Array initialization lists shall include a space after
the opening brace, after each comma, and a space before the closing
brace. If an initialization list extends past the text width then it
shall be broken into segments of 5 elements per line, with the first
five being listed on the same line as the variable name and each
following line of elements aligned with the elements above it.

#### Example

```C
/**
 * @brief  Get a cached copy of a static web page.
 * @para   location: a pointer to a managed string containing the location of the requested resource.
 * @return NULL on failure, 
 *         pointer to an http content object with the contents of the requested resource on success.
 */
http_content_t *
http_get_static (stringer_t *location)
{
	multi_t key = { .type = M_TYPE_STRINGER, .val.st = location };

	if (!content.pages) {
		return NULL;
	}

	return inx_find(content.pages, key);
}
```

### Pointers

Pointers shall never have a space between the `*` or `&` and the
variable name, even during declaration/definition.

#### Example

```C
int
function(void)
{
    unsigned char *buf = NULL;
    unsigned char c    = 0;
    unsigned char *tmp = NULL;

    ...

    c = *buf;
    tmp = &c;

    ...
}
```

### Function Calls

A function call shall be placed at the current indentation level 
one line with all arguments separated by a comma and a single
space. If the argumnts extend past the text width, the first
shall go on the function invocation line and all following arguments shall be placed on
their own lines and indented one tab from the function invacation. The terminating
parenthesis and semi-colon shall be placed on the same line and
immediately after the final argument. When parameters are spread across
multiple lines, no space shall follow the separating comma.

#### Example

```C
int32_t
function(void)
{
    ...

    otherFunction(var1, 5, NULL);

    var2 = thisFunction(buf,
        bufLen,
        outBuf,
        outLen);

    reallyLongFunctionName(superLongParameterName1,
        superLongParameterName2,
        superLongParameterName3);

    ...
}
```

### If, Else If, and Else Statements

If statements shall have a space separating the `if` and the opening
parenthesis of the conditional statement. Braces shall always be used to
contain the statements being executed for the condition, even if only
one statement exists.  The conditional
statement shall not have space between itself and the encapsulating
parenthesis. If a constant is used in the comparison then it shall be
placed on the left side of the comparison.

When multiple conditional statements are used, the first will go on the
same line as the `if`, with all following conditional statements on
their own lines following the first and aligned with the first
conditional statement. Each conditional statement will be encapsulated
in a set of parenthesis. The operators which link separate conditional
statements will be placed at the end of the line, with one space
separating the closing parenthesis of the conditional statement and the
logical operator. If conditional statements need to be nested (e.g.
(arg1 && arg2) || (arg3 && arg4)) then each distinct group shall be
formatted as described above with the operator comparing the two groups
going on its own line. Conditional statements shall only be nested once.

`else if` and `else` statements shall be placed on their own line at the
same indentation level as the `if` statement which they follow.

#### Example

```C
bool_t 
chr_punctuation (uchr_t c) 
{
	if ((c >= '!' && c <= '/') || 
      (c >= ':' && c <= '@') || 
      (c >= '[' && c <= '`') || 
      (c >= '{' && c <= '~')) {
		return true;
	}

	return false;
}
```

### Switch Statements

Switch statements shall have a space separating the `switch` and the
opening parenthesis which encloses the object being switched on. Braces
enclosing the case statements shall be placed on their own lines at the
same indentation level as the `switch`. The `case`s shall be placed on
their own lines and aligned at the same indentation level as the
`switch` with no space between the constant-expression and the colon.
The statements being executed for the space shall be indented by one
level. Braces shall not be used to contain the statements to be executed
for a given case. The default case shall be listed last and contain a
break statement. Whenever the same set of statements is to be executed
for multiple cases, each case shall be placed on its own line with a
comment of the form, `/* Fallthrough */`, placed on its own line
immediately preceding the first case in the group. Cases shall be listed
in alphanumeric order when possible.

*CAUTION:* If a variable is declared with an initializer before the first `case` statement,
the variable will have scope inside the switch block but will **not be initialized** and
will consequently contain an indeterminate value.

### Example

```C
int32_t 
function (void) 
{
    ...

    switch (input) {
    case 'a':
        options |= OPTION_ALL;
        break;
    case 'r':
        options |= OPTION_RECURSIVE;
        break;
    case 'V':    // fallthrough
    case 'v':
        options |= OPTION_VERBOSE;
        break;
    case default:
        break;
    }

    ...
}
```

### Loop Statements

For loops shall have a space separating the `for` and the opening
parenthesis of the control expressions. Control statements shall have a
space after each semi-colon and no space between the expressions and
their enclosing parenthesis. If the control expressions extend beyond
the text-width then each expression shall be placed on its own line,
except for the first which shall be placed on the same line as the
`for`. The separating semi-colons shall be placed on the same line as
the control expressions which they terminate. If multiple statements
exist in a single control expression, a space shall follow the comma
which separates them. Braces containing the iteration statements are
required and shall be placed on their own lines at the same indentation
level at the `for`.

Do-while loops shall have the `do` placed on its own line and braces,
which are required, shall have the opening brace placed on its own line
immediately following the `do`. The terminating brace shall be placed on
the line immediately following the last iteration statement. The `while`
will be placed on the same line as the terminating brace with a single
space on either side of the `while` keyword, followed by the control
statement placed in parenthesis and finally the semi-colon terminating
the do-while loop.

While loops shall have a space between the `while` and the opening
parenthesis of the control expression. The opening brace shall be placed
on its own line immediately following the line containing the `while`
and be placed at the same indentation level of the `while`. The closing
brace shall be placed on its own line immediately following the last
iteration statement.

Iteration statements shall be placed at one indentation level in from
the loop statement. Control statements for do-while and while loops
should be formatted the same way as `if` statements.

#### Example

```C
int32_t 
function (void) 
{
	int32_t i = 0;

    for (i = 0; i < 5; i++) {
        ...
    }

    do {
        ...
    } while (i < 5);

    while (i < 5) {
        ...
    }

    ...
}
```

### Return Statements

Functions shall have a single return
statement. The return value shall not be wrapped in parenthesis unless
the return value is not a constant expression or variable.

#### Example

```c
uint32_t 
pool_get_timeout (pool_t *pool) 
{
	if (!pool)
		return 0;

	return pool->timeout;
}
```

### Goto and Label Statements

`goto`s and `label`s shall not be used.

### Preprocessor Directives

Preprocessor directives shall be indented and their contents shall
be indented one level according to the preceding code. Nested preprocessor
directives shall indent by one level for each nesting. Each `#endif`
shall include a comment on the same line which specifies which `#if` it
is matched with.

#### Example

```C
#ifdef WINDOWS
    #define DPRINTF(x)  OutputDebugString(x)
#else
    #define DPRINTF(x)  perror(x)
#endif // WINDOWS

int32_t 
function (unsigned char *buf, int32_t len) 
{
    if (0 == count) {
		#ifdef WINDOWS
			OutputDebugString(L"Count was 0\n");
		#elif defined LINUX
			perror("Count was 0\n");
		#endif // WINDOWS
    }

    return 0
}
```

## Security

The following list was taken from the Software Engineering Institute's
[CERT Coding Standards](https://www.securecoding.cert.org/confluence/display/seccode/SEI+CERT+Coding+Standards).
The CERT document contains a wealth of programming information.


Top 10 Secure Coding Practices

1. **Validate input**. Validate input from all untrusted data sources. Proper input validation can eliminate
the vast majority of software vulnerabilities. Be suspicious of most external data sources, including command
line arguments, network interfaces, environmental variables, and user controlled files.

1. **Heed compiler warningx**. Compile code using the highest warning level available for your compiler and
eliminate warnings by modifying the cod. Use static and dynamic analysis tools to detect 
and eliminate additional security flaws.

1. **Architect and design for security policies**. Create a software architecture and design your software to 
implement and enforce security policies. For example, if your system requires different privileges at different
times, consider dividing the system into distinct intercommunicating subsystems, each with an appropriate privilege set.
    
1. **Keep it simple**. Keep the design as simple and small as possible. Complex designs increase the likelihood
that errors will be made in their implementation, configuration, and use. Additionally, the effort required 
to achieve an appropriate level of assurance increases dramatically as security mechanisms become more complex.

1. **Default deny**. Base access decisions on permission rather than exclusion. This means that, by default, 
access is denied and the protection scheme identifies conditions under which access is permitted.

1. **Adhere to the principle of least privilege**. Every process should execute with the the least set of 
privileges necessary to complete the job. Any elevated permission should be held for a minimum time.
This approach reduces the opportunities an attacker has to execute arbitrary code with elevated privileges.

1. **Sanitize data sent to other systems**. Sanitize all data passed to complex subsystems such as command shells,
relational databases, and commercial off-the-shelf (COTS) components. Attackers may be able to invoke unused 
functionality in these components through the use of SQL, command, or other injection attacks. 
This is not necessarily an input validation problem because the complex subsystem being invoked does not understand
the context in which the call is made. Because the calling process understands the context, it is responsible for 
sanitizing the data before invoking the subsystem.

1. **Practice defense in depth**. Manage risk with multiple defensive strategies, so that if one layer
of defense turns out to be inadequate, another layer of defense can prevent a security flaw from becoming 
an exploitable vulnerability and/or limit the consequences of a successful exploit. For example, combining
secure programming techniques with secure runtime environments should reduce the likelihood that vulnerabilities 
remaining in the code at deployment time can be exploited in the operational environment.

1. **Use effective quality assurance techniques**. Good quality assurance techniques can be effective in identifying
and eliminating vulnerabilities. Fuzz testing, penetration testing, and source code audits should all be 
incorporated as part of an effective quality assurance program. Independent security reviews can lead to more
secure systems. External reviewers bring an independent perspective; for example, in identifying and correcting
invalid assumptions.

1. **Adopt a secure coding standard**. Develop and/or apply a secure coding standard for your target development language and platform.

#### Bonus Secure Coding Practices

1. **Define security requirements**. Identify and document security requirements early in the development 
life cycle and make sure that subsequent development artifacts are evaluated for compliance with those
requirements. When security requirements are not defined, the security of the resulting system cannot be effectively evaluated.

1. **Model threats**. Use threat modeling to anticipate the threats to which the software will be subjected.
Threat modeling involves identifying key assets, decomposing the application, identifying and categorizing
the threats to each asset or component, rating the threats based on a risk ranking, and then developing 
threat mitigation strategies that are implemented in designs, code, and test cases.

### Avoid information leakage in structure padding

The C99 Standard specifies that non-bit-field structure members are aligned in an implementation-defined manner
and that there may be padding within or at the end of a structure. Furthermore, initializing the members of the
structure does not guarantee initialization of the padding bytes. The standard says

>When a value is stored in an object of structure or union type, including in a member object, the bytes 
>of the object representation that correspond to any padding bytes take unspecified values.

When passing a structure pointer to a different trusted domain, one must ensure that the padding bytes of the structure does 
not contain sensitive information.
