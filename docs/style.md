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

#### Example

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

### Compiler Warnings

A compiler warning is the compiler's message that a construct is risky, produces an undefined or implementation defined result,
or indicates the possible presence of an error. Treat warnings as if they are recommendations from the compiler writers, because
that is what they are. Do not suppress warnings without an excellent and documented reason.
Code should compile cleanly with warnings enabled. Any warnings that remain should be carefully documented in the code with a
reason why the warning could not be easily removed.

For GCC, some options, such as `-Wall` and `-Wextra`, turn on other options, such as `-Wunused`, which may turn on further options,
such as `-Wunused-value`. When combining multiple options, more specific options have priority 
over less specific ones, independent of their position in the command-line. For options of the same specificity, the last
one takes effect. Options enabled or disabled via `#pragma` take effect as if they appeared at the end of the command-line. 


Suggested GCC compiler flags:

```
-Wall -Wextra -Wformat-nonliteral -Wcast-align -Wpointer-arith -Wbad-function-cast \
-Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Winline -Wundef \
-Wnested-externs -Wcast-qual -Wshadow -Wwrite-strings -Wno-unused-parameter \
-Wfloat-equal -pedantic -ansi
```

Consult the compiler documentation for the definition and explanation of each compiler flag.

## Defining and Declaring Objects

In C, **declaring** an object means giving the *name* and *type* of the object. An object
may be declared multiple times if all the declarations are consistent. **Defining** an
object creates storage for the object. **Defining** a function means providing the
function's body. A definition counts as a declaration, but an object may only be defined once.

### C99 Integer types

Prefer the **C99** types, declared in `<stdint.h>`

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
is necessary to know how the compiler behaves when the standard volatile behavior is required.

The paper's authors tested a workaround by wrapping volatile accesses with function calls. They describe it with the 
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

#### Example Declarations and Definitions

```C
extern int64_t size;

typedef struct memoryblock
{
	uint_32  size;
	uint64_t length;
	void     *data;
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

Objects should be declared in the minimum scope for which all references are possible. Variables and functions that
are not required to be visible outside a single file should be declared as `static`. This
increases the modularity of the code and reduces the number of names in in the global namespace.

### Global Variables

Global variables shall have no indentation and will use a single space
to separate the type, name, equals sign, and the initialization value.
If multiple global variables exist in the same file then the variable
types, names, equals signs, and initialization values shall be column
aligned.

### Local Variables

Local function variable definitions shall be placed at the current indentation level.
Variable definitions and declarations at the same indentation level shall have names,
equal signs, and initilization values column aligned. If only one local
variable exists then a single space may be used to separate the variable
type, variable name, and equals sign.

All variables shall be initialized to a meaningful value. If no meaningful value exists yet
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
brace. If an initialization list extends past the line's text width then it
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

#### Exception

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


### Function Definitions and Prototypes

A function prototype or definition shall not be indented, except for the
parameter list as decribed below. It shall be formatted such that the
return type is placed first, then the function name on a new line, and
then the parameters. One space shall separate the function name from the opening parenthesis 
of the parameter list. Parameters shall go on the same line
as the function name unless they will extend past the line's text width or
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

## Statement Formatting

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

## Executable Code

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

```C
if (!(point = EC_KEY_get0_public_key_d(key))) {
	log_info("No public key available. {%s}", ERR_error_string_d(ERR_get_error_d(), NULL));
	return NULL;
} else if (!(group = EC_KEY_get0_group_d(key))) {
	log_info("No group available. {%s}", ERR_error_string_d(ERR_get_error_d(), NULL));
    return NULL;
} else if (!(result = mm_alloc(blen))) {
	log_info("Error allocating space for ECIES public key.");
    return NULL;
} else if ((rlen = EC_POINT_point2oct_d(group, point, POINT_CONVERSION_COMPRESSED, result, blen, NULL)) <= 0) {
	log_info("Unable to extract the public key. {%s}", ERR_error_string_d(ERR_get_error_d(), NULL));
	mm_free(result);
	return NULL;
}
```

All assignments in conditional statements should not be *bare*. That is, the assignment
should be enclosed in parenthesis and an explicit comparison made to denote the intnetionality
of the assignment.

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
comment of the form, `// fallthrough`, placed on  the same line as
the first case in the group. Cases shall be listed
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

Iterated statements shall be placed at one indentation level in from
the enclosing loop statement.
Braces enclosing the iterated statements are required. Loop control expressions
should be formatted the same way as conditional expressions for `if` statements.
The control expressions should express all condtions under which the loop will exit;
`break` statements should not be used.

For-loops shall have a space separating the `for` and the opening
parenthesis of the control expressions. Control statements shall have a
space after each semi-colon and no space between the expressions and
their enclosing parenthesis. If the control expressions extend beyond
the line text-width then each expression after the first shall be
indented one level and placed on its own line.
Semicolons shall be placed on the same line as
the control expressions which they terminate.
The opening brace is placed on the same line as the last control expression.
The closing brace shall be placed on its own line at the same indentation
level at the `for`.

Do-while loops shall have the `do` placed on its own line.
The opening brace is placed immediately following and on the same line as the `do`.
The terminating brace shall be placed on
the line immediately following the last iterated statement. The `while`
will be placed on the same line as the terminating brace with a single
space on either side of the `while` keyword, followed by the control
statement placed in parenthesis and finally the semi-colon terminating
the do-while loop.

While loops shall have a space between the `while` and the opening
parenthesis of the control expression. The opening brace shall be placed
on the same line and immediately following the `while` control expression.
The closing brace shall be placed on its own line immediately following the last
iteration statement at the same indentation level as the `while`.

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
statement. Additional return statements may be used only in error handling code.
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

`goto`s and `label`s shall not be used, except in the resource Allocation Pattern discussed below.

### Preprocessor Directives

Preprocessor directives shall 
be indented according to the code that precedes it. Nested preprocessor
directives shall indent by one level for each nesting level. Each `#endif`
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

### Function Calls

A function call shall be placed at the current indentation level 
on one line with all arguments separated by a comma and a single
space. If the argumnts extend past the line's text width, the first
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

##Comments

### Single Line Comments

A single line comment shall be introduced with the characters `//` and 
placed on its own line, indented to
the same level of the code which immediately follows it.

If no code follows the comment then it shall not be indented.

#### Example

```c

    // This is a single line comment
    int hello(void) {
    
        // Single line comment with code that mandates indenting the comment
        printf("Hello, world!");
        return 0;
    }
    
    // Single line comment with no code following it

```

### Multiline Comments

A multiline comment is introduced with the characters `/*` and terminated with the
characters `*/`. Each line between the beginning and ending lines shall
begin with the characters `* ` aligned with the matching characters in
the comment delimeters. A multiline comment shall follow the same indentation rules 
for a single line comment.

#### Example

```c
int hello(void) {
 
        /*
         * A multiline comment indented appropriately
         */
        printf("Hello, world!");
        return 0;
}

    /*
     * A multiline comment with no code following it
     */

```

### Variable Comments

Global and static variables shall be commented.

### Implementation Comments

Particularly tricky or important sections of code shall be commented but
should not duplicate information which is clearly indicated by the code
itself.

### Todo Comments

**Todo** comments shall be used to describe code which is meant only as a
temporary solution or as a note for functionality that should be
implemented in the future. **Todo** comments shall begin with the text `TODO`
followed by parenthesis containing the name of the person
making the comment, a colon and a space, and then the comment itself.

#### Example

```c

    // TODO(fred): Insert new constants before release

    /*
     * TODO(Fred):
     * This should really be implemented to allow IPv6 connections
     * and name resolution.
     */

```

### Function comments

Every function shall be commented with Javadoc style comments for use by Doxygen.

Function prototypes shall not be commented.

A function comment will be of the form of the example following.
The @brief, @param, and @return tags are required.
The @note on the function's behavior is optional, but highly encouraged if the functions's 
behavior is not immediately apparent from the code.
Each @param consists of a brief description of a single parameter on its own line. 
The @return tag consists of a short description of the function's return value. If special
values are returned, each special return value with its meaning

Standard library functions shall use descriptions found in the standard.

#### Example

```c
/**
 * @brief	Free a managed string.
 * @see		st_valid_free(), st_valid_opts()
 * @note	Any managed string to be freed should conform with the validity checks enforced by st_valid_free()/st_valid_opts()
 * 			*NO* managed string should be passed to st_free() if it was allocated on the stack, or contains foreign data.
 * 			The following logic is carried out depending on the allocation options of the string to be freed:
 * 			Jointed placer:	Free header, if secure or on heap
 * 						Free underlying data if it is not foreign
 * 			Jointed nuller:	Free header and underlying data
 * 			Jointed block:	Free header and underlying data
 * 			Jointed managed:	Free header and underlying data
 * 			Jointed mapped:	Free the header and (munmap) underlying data
 * 			Contiguous nuller:	Free header (this includes the underlying data because they are already merged)
 * 			Contiguous block:	Free header (this includes the underlying data because they are already merged)
 * 			Contiguous managed:Free header (this includes the underlying data because they are already merged)
 *
 * @param	s	the managed string to be freed.
 * @return	This function returns no value.
 */
void st_free(stringer_t *s) {

   [...]
}
```

### File Comments

Each file must begin with a Javadoc style header comment for use by Doxygen. 
The @file and @author tags are required.

#### Example

```c
/**
 * @file /magma/core/hash/adler.c
 * @author Ivan Tolkachev
 *
 * @brief	An x86 implementation of the Adler hash algorithm.
 *
 */
```

### Javadoc tags

Tag and Parameter | Description | Notes
---- | ---- |---- 
@file | file name | Name of the current file
@brief | description | Brief description of the functionality
@author | author name | One per author, in chronological order
@version | version | Version number
@since | text | Describes release when this functionality was created
@see | reference | Link to other element of documentation
@param | name | Describes a parameter
@return | description | Describes the return value
@deprecated | description | Describes release when this functinoality was outdated

## Function Organization

Typically a function carries out several tasks; collecting input, allocating resources, perform work, deallocating
resources, returning output, and handling failures.
Well structured functios carry out their tasks in that order. First, input parameters are validated, then resources needed for the work are fetched or allocated,
the work is carried out, temporary resources are deallocated, and the computed output is returned to the caller.
The C language doesn't have many high level constructs for handling failure, so we must use certain idiomatic patterns for
handling the inevitable failures that happen.

One such pattern is to validate the value of a passed parameter. If the value is out-of-range, the function can return an error immediately.
Several 'if' statements may be necessary to validate all input parameters, and each can terminate the function if
the value is unsuitable.

It is often useful to log when parameter errors occur, especially during testing.

#### Example Parameter Checking Pattern

```C
if (my_first_param < 0) {
	return error_value;
}

if (my_second_param > MAX_VALUE) {
	return error_value;
}
```

Next, resources are allocated, and the temporary resources should be deallocated in reverse order after the work has been performed.
Should an allocation fail, it is permissible to jump forward in the code to the deallocation section and begin deallocating 
resources that had previously been created. This is the only pattern where a `goto` statement may be used. This pattern is clear, and
slightly cleaner than successively nesting code inside an `if` for a successful allocation. 

#### Example Allocation Pattern

```C
	/*
	 * Allocate temporary resources
	 */

	if ((res1 = alloc(param)) == ERROR) {
		goto error_res1;
	}

	if ((res2 = alloc(param2)) == ERROR) {
		goto error_res2;
	}

	if ((res3 = alloc(param3)) == ERROR) {
		goto error_res3;
	}

	// perform work

	/*
	 * Deallocate all temporary resources
	 */

	dealloc(res3);

error_res3:
	dealloc(res2);

error_res2:
	dealloc(res1);

error_res1:
	if (error_occurred)
		return error_value;

	return calculated_value;
}
```

## File Organization

Code is organized into groups of related functions, called a *module* in most programming languages.
A header file (.h file) declares the interface of your module. An implementation file (.c file)
contain the code for a module.
If a function in a module is used in other modules (i.e., other .c files), place the 
function's prototype in a .h interface file. By including this interface file in your original module's .c file 
and every other .c file calling the function, the compiler makes the function visible to other modules.

If you only need a function in a certain .c file (not in any other module), declare its scope `static`.
This means it can only be called from within the c file it is defined in. 

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

// contents of my_header.h

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

### Function Definitions and Prototypes

A function prototype or definition shall not be indented, excluding the
parameter list as decribed below. It shall be formatted such that the
return type is placed first, then the function name on a new line, and
then the parameters. One space shall separate the function name from the opening parenthesis 
of the parameter list. Parameters shall go on the same line
as the function name unless they will extend past the line's text width or
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
brace. If an initialization list extends past the line's text width then it
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
on space. If the argumnts extend past the line's text width, the first
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

### Beware code optimization

A C99 conforming compiler "need not evaluate part of an expression if it can deduce that its value is not used and
that no needed side effects are produced (including any caused by calling a function or accessing a volatile object)."

The process of compiler optimization may result in the compiler removing code determined 
to be not needed but has been added for a specific (often security-related) purpose.
