Formatting
----------

### Character Encoding

Files should only contain characters that are part of the UTF-8
character set defined by RFC3629. For code which is not implementing
locale-specific functionality only the first 128 characters of UTF-8
shall be used, i.e. the characters in the ASCII character set defined by
RFC20.

### Line Length/Text Width

The maximum length of any one line shall be 80 characters.

#### Exception

String constants may break this rule so that any substring may be
searched for without worrying whether the substring is split across
multiple lines.

#### Example

```c

    void usage(void)
    {
        printf("Usage: program [--verbose] [--format] -i <input files> -o <output files>\n");
    }

```

### Tabs and Spaces

A tab shall consist of four spaces and not an actual tab character.

### Indentation

Each level of indentation shall add one tab to the previous level.

### Tabular Alignment

Tabular alignment refers to aligning rows of text into columns aligned
on tab boundaries. It is used when describing the formatting of groups
of items like parameter lists or local variables. Tabular alignment
means that each successive column will be placed one tab boundary away
from the longest entry in the previous column such that at least one
space exists between the longest entry and the following column’s data.
If every item in a single column are the same length, then a single
space shall be used instead of inserting multiple spaces to reach the
next tab boundary.

### Example

```c

    int         gCount  = 0;
    char        *gBuf   = NULL;
    long int    gSize   = 0;

    void
    function(
        char    *inBuf,
        size_t  inSize,
        char    *outBuf,
        size_t  outSize)
    {
        int     i       = 0;
        size_t  sIn     = 0;
        size_t  sOut    = 0;
        char    *tmp    = NULL;

        ...
    }

```

### Operator Spacing

Spaces should always be placed on either side of an operator, unless the
operator is the last character in a line.

### Parenthesis

Parenthesis shall be used to explicitly define order of operations
unless all operators share the same order of precedence.

### Files

Each file shall consist of the following groups, in this order:

-   File comment
-	Header guard
-   `#include` statements
-   `#define` statements
-   `enum`, `struct`, and `union` definitions
-   Type declarations
-   Function prototypes
-   Function definitions

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

```c

    #ifndef MY_HEADER_H
    #define MY_HEADER_H

    ...

    #endif /* MY_HEADER_H */

```

### Include Statements

Include statements shall have one space between the `#include` and the
header name being included. They shall be placed in two groups,
separated by a blank line: system headers and local header. When
possible, they should be sorted alphabetically.

#### Example

```c

    #include <stdio.h>
    #include <sys/stat.h>

    #include "common.h"
    #include "sorting.h"

```

### Define statements

Define statements shall have on space between the `#define` and the
identifier. The identifier and replacement-list shall be tabularly
aligned. For replacement-lists which only consist of a single char,
integer, or float value, the replacement-list shall be enclosed in
parenthesis. For replacement-lists which span multiple lines, align the
`\`s at the column after one space is added to the longest line in the
replacement-list.

#### Example

```c

    #define MAX_SIZE            (256)
    #define MODULE_NAME         "stdio"
    #define PRINT_ARRAY(x)      do                                               \
                                {                                                \
                                    int i = 0;                                   \
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
and names shall be tabularly aligned in structures and unions, while
enumeration constant names, equals signs, and their values shall be
tabularly aligned and include a comma after the last enumeration
constant.

#### Example

```c

    typedef struct myStruct
    {
        unsigned int    member1;
        long            member2;
    } MyStruct;

    typedef union myUnion
    {
        unsigned long   member1;
        unsigned char   member2;
    } myUnion;

    typedef enum color
    {
        BLUE    = 1,
        GREEN   = 2,
        RED     = 3,
    } Color;

```

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

The type specifier shall be the least verbose version of the
corresponding set listed in the standard, one of:

-   `void`
-   `signed char`
-   `unsigned char`
-   `short`
-   `unsigned short`
-   `int`
-   `unsigned int`
-   `long`
-   `unsigned long`
-   `float`
-   `double`
-   `long double`
-   struct or union specifier
-   enum specifier
-   typedef name

`char` and an implied `int` shall not be used.

The storage-class, qualification, and type specifier will collectively
be referred to as a variable’s type.

Each variable shall be declared on its own line.

#### Example

```c

    typedef unsigned short  uint16;

    extern long             size;

    typedef struct memoryBlock
    {
        unsigned int    size;
        signed long     length;
        void            *data;
    } MemoryBlock;

    typedef enum
    {
        BLUE    = 1,
        GREEN   = 2,
        RED     = 3,
    } Color;

    void
    function(void)
    {
        unsigned char           c           = 0;
        short                   s           = 0;
        register unsigned int   i           = 0;
        signed long int         l           = 0L;
        static const float      f           = 0.0F;
        volatile double         d           = 0.0F;
        static long double      ld          = 0.0F;
        unsigned char           *pC         = NULL;
        unsigned int            aScores[10] = { 0 };

        ...
    }

```

### Function Definitions and Prototypes

A function prototype or definition shall not be indented excluding the
parameter list as decribed below. It shall be formatted such that the
return type is placed first, followed by one space, then the function name and
parameters. No spaces shall separate the function name from the opening parenthesis 
of the parameter list. No space  Parameters shall go on the same line
as the function name unless they will extend past the text width or
there are more than three parameters. In these two cases the opening
parenthesis of the parameter list shall go on the same line as the
function name and the parameter list shall begin on the following line.
The parameter list shall be indented by one tab and have the parameter
types and names tabularly aligned. Parameters which fit on the same line
as the function name shall have 1 space following each `,` character
which separates the parameters. If a parameter takes no functions then
`void` shall take the place of the parameter list.

Function braces shall be placed as follows.
The opening brace shall be placed one space after the parameter list closing parenthesis. 
The closing function brace shall be placed on the line immediately following the last
statement in the function, at the same indentation level as the function declaration.

#### Example

```c

/**
 * @brief	Set the domain name and reverse lookup status of a connection.
 * @note	Possible values for status include REVERSE_ERROR, REVERSE_EMPTY, REVERSE_PENDING, and REVERSE_COMPLETE.
 * @param	domain	the new value of the connection's hostname.
 * @param	status	the new value of the connection's reverse lookup status.
 * @return	This function returns no value.
 */
void con_reverse_domain(connection_t *con, stringer_t *domain, int_t status) {

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
types, names, equals signs, and initialization values shall be tabularly
aligned.

### Local Variables

Local function variables shall be placed one indentation level in
from the function declaration. The variable types, names, equals signs, and
initilization values shall be tabularly aligned. If only one local
variable exists then a single space may be used to separate the variable
type, variable name, and equals sign.

All types shall be initialized to a meaningful value, if none exists yet
then they shall be initialized according to the following rules. All
integer types shall be initialized to `0` and `0L` for `long` types; all
floating types shall be initialized to `0.0F`; all char types shall be
initialized to `0`; all pointer types shall be initialized to `NULL`;
all array types shall be initialized to `{ 0 }`; all enumeration types
shall be initialized to `0`; all structure types and union types shall
be uninitialized. Array initialization lists shall include a space after
the opening brace, after each comma, and a space before the closing
brace. If an initialization list extends past the text width then it
shall be broken into segments of 5 elements per line, with the first
five being listed on the same line as the variable name and each
following line of elements aligned with the elements above it.

#### Example

```c

/**
 * @brief	Get a cached copy of a static web page.
 * @param	location	a pointer to a managed string containing the location of the requested resource.
 * @return	NULL on failure, or a pointer to an http content object with the contents of the requested resource on success.
 */
http_content_t * http_get_static(stringer_t *location) {

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

```c

    int
    function(void)
    {
        char    *buf    = NULL;
        char    c       = 0;
        char    *tmp    = NULL;

        ...

        c = *buf;
        tmp = &c;

        ...
    }

```

### Function Calls

A function call shall be placed at the current indentation level and
written on one line with all arguments separated by a comma and a single
space. If there are more than three arguments being passed to the
function or the three arguments extend past the text width, the first
shall go on the same line and all following arguments shall be placed on
their own lines and aligned with the first argument. The terminating
parenthesis and semi-colon shall be placed on the same line and
immediately after the final argument. When parameters are spread across
multiple lines, no space shall follow the separating comma.

#### Example

```c

    int
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
one statement exists. Braces shall be placed at the same indentation
level as the `if` and will be placed on their own lines. The conditional
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

```c

    int
    function(void)
    {
        ...

        if (3 < argc)
        {
            printUsage();
            exit(1);
        }

        if (1 == count)
        {
            ...
        }
        else if (2 == count)
        {
            ...
        }
        else
        {
            ...
        }

        if ((NULL == pMem) ||
            (0 == strlen(msg)))
        {
            return -1;
        }

        if (((0 == arg1) &&
             (5 <= arg2))
            ||
            ((NULL == pSrc) &&
             (NULL == pDst)))
        {
            ...
        }

        ...
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

```c

    int
    function(void)
    {
        ...

        switch (input)
        {
        case 'a':
            options |= OPTION_ALL;
            break;
        case 'r':
            options |= OPTION_RECURSIVE;
            break;
        /* Fallthrough */
        case 'V':
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
their enclosing parenthesis. If the control expressions extend beyong
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

```c

    int
    function(void)
    {
        ...

        for (i = 0; i < 5; i++)
        {
            ...
        }

        do
        {
            ...
        } while (i < 5);

        while (i < 5)
        {
            ...
        }

        ...
    }

```

### Return Statements

Functions which have a non-void return type shall have a single return
statement. The return value shall not be wrapped in parenthesis unless
the return value is not a constant expression or variable.

A second return statement is allowed for immediately returning if
parameter checking fails.

#### Example

```c

    int
    function(char *buf, int len)
    {
        int ret = 0;

        if ((NULL == buf) ||
            (0 == len))
        {
            return -1;
        }

        ...

        return ret; 
    }

```

### Goto and Label Statements

`goto`s and `label`s shall not be used.

#### Example

```c

    /* Nothing is here because you shouldn't use goto or label */

```

### Preprocessor Directives

Preprocessor directives shall not be indented and their contents shall
be indented according to the code that precedes it. Nested preprocessor
directives shall indent by one level for each nesting. Each `#endif`
shall include a comment on the same line which specifies which `#if` it
is matched with.

#### Example

```c

    #ifdef WINDOWS
        #define DPRINTF(x)  OutputDebugString(x)
    #else
        #define DPRINTF(x)  perror(x)
    #endif /* WINDOWS */

    int
    function(char *buf, int len)
    {
        if (0 == count)
        {
    #ifdef WINDOWS
            OutputDebugString(L"Count was 0\n");
    #elif defined LINUX
            perror("Count was 0\n");
    #endif /* WINDOWS */
        }

        ...
    }

```