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

A multiline comment is introduced with the characters `/**` and terminated with the
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
It shall contain a brief description, an optional reference to related functions,
an option set of notes on the function's behavior, a brief description of each parameter
on its own line, and a short description of its return value. If special
values are returned, each value with its meaning
meaning shall be listed on its own lines. Descriptive text shall be aligned.

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

#### Example

```c
/**
 * @file /magma/core/hash/adler.c
 *
 * @brief	An x86 implementation of the Adler hash algorithm.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */
```

### Javadoc tags

Tag and Parameter | Usage | Description
—— | —— | ——
@author | John Smith | Describes an author.
@version | version | Version number.
@since | since-text | Describes when this functionality first existed.
@see | reference | Provides a link to other element of documentation.
@param | name description | Describes a parameter.
@return | description | Describes the return value.
@Deprecated | description | Describes an outdated method.




