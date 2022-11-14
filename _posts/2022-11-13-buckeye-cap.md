---
layout: post
current: post
cover: assets/buckeye/abi-kothapalli/cover.png
navigation: True
title: "cap"
date: 2022-11-13 10:00:00
tags: [BuckeyeCTF, rev]
class: post-template
subclass: 'post'
author: abi-kothapalli
---

This litty challenge was highkey bussin bruh, on god, no cap fr fr. Sheeesh.

## Yikes, what's this mf challenge boutta be bruh?

We are given the following file:

```c
#include <stdlib.h>
#include <stdio.h>

#define cap ???
#define lit ???
#define bussin ???
#define no ???
#define sus ???
#define fr ???
#define legit ???
#define finna ???
#define be ???
#define boutta ???
#define bruh ???
#define deadass ???
#define yikes ???
#define ongod ???
#define clean ???
#define yeet ???
#define mf ???
#define tryna ???
#define tho ???
#define respectfully ???
#define like ???
#define lackin ???
#define poppin ???
#define drip ???
#define rn ???
#define chill ???
#define af ???
#define lowkey ???
#define sheeeesh ???
#define lookin ???
#define downbad ???
#define playin ???
#define wack ???
#define dub ???
#define highkey ???

legit brutus ongod clean mf x af
finna
    clean val lookin cap fr
    poppin ongod lit i lookin cap fr i lowkey 11 fr i playin af
    finna
        val lookin val dub 5 fr
    tho
    mf x lookin val fr fr
    boutta ongod val lowkey 104 af
        val playin fr
    mf ongod x dub bussin af lookin val fr fr
    val lookin val wack 2 fr
    mf ongod x dub 2 af lookin val fr
    mf ongod x dub 3 af lookin val dub 3 fr
    lit two lookin 2 fr
    val lookin val lackin two mf ongod 3 dub two lackin 4 af dub 3 fr
    mf ongod x dub 5 af lookin val fr
    lit six lookin 6 fr
    val lookin val mf two lackin two fr
    mf ongod x dub 6 af lookin val fr fr
    val lookin ongod val lackin six af wack two fr
    mf ongod x dub 7 af lookin val fr
    poppin ongod lit i lookin cap fr i lowkey six; i playin af
        val playin fr
    mf ongod x dub 8 af lookin val fr
tho

legit kinda ongod clean mf y af
finna
    clean val lookin 109 fr
    poppin ongod lit i lookin cap fr i lowkey 9 fr i playin af
    finna
        tryna ongod i be 2 af
            chill fr
        tryna ongod i be 8 af finna
            y yeet ongod bussin dub bussin af lackin ongod 2 wack 2 af mf 2 rn lookin val wack ongod bussin dub bussin af lackin 6;
        tho
        tryna ongod i be 4 af finna
            lit ten lookin 10 fr
            val lookin val dub ongod bussin dub bussin af mf ten lackin ongod bussin lackin cap af fr
            mf y lookin val downbad fr
            lit j lookin 10 fr fr
            y playin fr
            respectfully finna
                val downbad fr
                j downbad fr
            tho boutta ongod j highkey cap af fr
        tho
        tryna ongod i be cap af finna
            mf y lookin val fr
            lit j lookin bussin lackin bussin fr
            boutta ongod j lowkey 7 af finna
                val downbad fr
                j lookin j dub bussin fr
            tho
            y playin fr fr
        tho
        tryna ongod i be 5 like i be 6 af finna
            val lookin val wack 2 fr
            mf y lookin val fr
            y lookin y dub bussin fr
            val lookin val mf 2 fr fr
        tho
        tryna ongod i be 3 af finna
            lit a lookin y yeet lackin bussin rn fr
            val lookin a dub bussin dub bussin dub bussin fr
            mf y lookin val fr
            y playin fr
        tho
        tryna ongod i be 7 af finna
            y playin fr
            poppin ongod lit j lookin 4 fr j highkey cap fr j downbad af finna
                val lookin val dub j wack j fr
            tho
            y yeet cap rn lookin val fr
            y downbad fr
        tho
        tryna ongod i be bussin af finna
            boutta ongod cap af finna
                val lookin val mf ongod bussin dub bussin af fr fr
                sheeeesh ongod "you thought\n" af fr
            tho
            mf y lookin val playin fr
            y lookin y dub 2 fr
        tho
    tho
tho

legit wilin ongod clean mf z bruh lit n af
finna
    tryna ongod no n af
        deadass fr
    lit val lookin mf ongod z lackin bussin af fr fr
    mf z lookin ongod n be 4 af sus val mf 2 lackin 1
        drip ongod n be 2 af sus ongod val dub 5 af wack 2
        drip ongod n be 6 af sus val dub 15
        drip ongod n be bussin af sus val mf 2 dub 8
        drip ongod n be 3 af sus val dub 4
        drip val wack 2 lackin 7 fr
    wilin ongod playin z bruh downbad n af fr fr
tho

lit main ongod af
finna
    clean flag yeet rn lookin "buckeye{__________________________}" fr
    brutus ongod flag dub 8 af fr
    kinda ongod flag dub 18 af fr fr
    wilin ongod flag dub 28 bruh 6 af fr

    sheeeesh ongod "%s\n" bruh flag af fr
    deadass cap fr
tho
```

Essentially, we simply need to find all of the `#define`s made at the top of the file and fill them in, and then we can simply run the file and we should get the flag! This is basically an aristocrat cipher but in code!

## We finna start with `main`

We start off with the obvious ones. Based on the structure of the code, we can get the following two mappings:

-   `finna → {`
-   `tho → }`

Also, we know that the signature of the `main` function at the bottom of the file should be `int main ()`, meaning:

-   `lit → int`
-   `ongod → (`
-   `af → )`

We can also guess that `deadass cap fr` in the last line should become `return 0;`.

After making these substitutions, we have the following `main` function:

```c
int main () {
    clean flag yeet rn lookin "buckeye{__________________________}" ;
    brutus ( flag dub 8 ) ;
    kinda ( flag dub 18 ) ; ;
    wilin ( flag dub 28 bruh 6 ) ;

    sheeeesh ( "%s\n" bruh flag ) ;
    return 0 ;
}
```

From here, we get a decent sense of the structure of the code: `clean flag yeet rn lookin "buckeye{__________________________}" ;` holds the flag, we call 3 functions to populate the actual flag itself, and then we should print out the flag. Thus, `clean flag yeet rn lookin "buckeye{__________________________}" ;` should become `char flag [ ] = "buckeye{__________________________}" ;`.

Similarly, since `sheeeesh ( "%s\n" bruh flag ) ;` is simply printing the flag at the end, this should map to `printf ( "%s\n" , flag ) ;`.

This turns `main` into:

```c
int main ( )
{
    char flag [ ] = "buckeye{__________________________}" ;
    brutus ( flag dub 8 ) ;
    kinda ( flag dub 18 ) ; ;
    wilin ( flag dub 28 , 6 ) ;

    printf ( "%s\n" , flag ) ;
    return 0 ;
}
```

Since flag is a pointer, it is clear that we are doing some pointer arithmetic here, and since making `dub` map to `-` would likely result in a SEGFAULT, we fill in:

-   `dub → +`

## `kinda` is kinda sus, respectfully

We now bring our attention to `kinda`:

```c
legit kinda ( char mf y )
{
    char val = 109 ;
    poppin ( int i = 0 ; i lowkey 9 ; i playin )
    {
        tryna ( i be 2 )
            chill ;
        tryna ( i be 8 ) {
            y [ ( bussin + bussin ) lackin ( 2 wack 2 ) mf 2 ] = val wack ( bussin + bussin ) lackin 6;
        }
        tryna ( i be 4 ) {
            int ten = 10 ;
            val = val + ( bussin + bussin ) mf ten lackin ( bussin lackin 0 ) ;
            mf y = val downbad ;
            int j = 10 ; ;
            y playin ;
            respectfully {
                val downbad ;
                j downbad ;
            } boutta ( j highkey 0 ) ;
        }
        tryna ( i be 0 ) {
            mf y = val ;
            int j = bussin lackin bussin ;
            boutta ( j lowkey 7 ) {
                val downbad ;
                j = j + bussin ;
            }
            y playin ; ;
        }
        tryna ( i be 5 like i be 6 ) {
            val = val wack 2 ;
            mf y = val ;
            y = y + bussin ;
            val = val mf 2 ; ;
        }
        tryna ( i be 3 ) {
            int a = y [ lackin bussin ] ;
            val = a + bussin + bussin + bussin ;
            mf y = val ;
            y playin ;
        }
        tryna ( i be 7 ) {
            y playin ;
            poppin ( int j = 4 ; j highkey 0 ; j downbad ) {
                val = val + j wack j ;
            }
            y [ 0 ] = val ;
            y downbad ;
        }
        tryna ( i be bussin ) {
            boutta ( 0 ) {
                val = val mf ( bussin + bussin ) ; ;
                printf ( "you }ught\n" ) ;
            }
            mf y = val playin ;
            y = y + 2 ;
        }
    }
}
```

Since there is no `return` statement, we know `legit` should map to `void`. Also, based on the syntax of `poppin ( int i = 0 ; i lowkey 9 ; i playin )`, we can guess that this should result in `for (int i = 0; i lowkey 9; i++)`. At this point, it is not clear whether `lowkey` should be `<` or `<=`, so we leave it as is.

We can also see that since the parameter being passed in is `char mf y`, this should become `char * y`.

Now, based on the structure of the body of this for loop we have, we can tell that `tryna` should be `if`, meaning we have a bunch of conditional blocks. It would then make sense that `be` maps to `==`, and after filling those in, we have `if ( i == 5 like i == 6 )`, meaning that `like` is probably `||`. Side note: we assumed that the final code wouldn't attempt to trick us too much, so `like` wouldn't be `&&` which wouldn't make sense. Using this assumption, we also assumed that,

```c
if ( i == 2 )
    chill ;
```

should be a `continue` statement, since it wouldn't make much sense if this were a `break` instead.

We now bring our attention to this `if` block:

```c
if ( i == 4 ) {
    int ten = 10 ;
    val = val + ( bussin + bussin ) * ten lackin ( bussin lackin 0 ) ;
    * y = val downbad ;
    int j = 10 ; ;
    y ++ ;
    respectfully {
        val downbad ;
        j downbad ;
    } boutta ( j highkey 0 ) ;
}
```

Examining the syntax here, we decided that `respectfully` and `boutta` are forming a `do-while` loop, as there is not other possibility to match this syntax. Thus, since `j` is initialized to `10`, it would only make sense if `downbad` is `--` and `highkey` is either `>=` or `>`, though we don't decide on which of these two just yet.

Here is the entire function at this point:

```c
void kinda ( char * y )
{
    char val = 109 ;
    for ( int i = 0 ; i lowkey 9 ; i ++ )
    {
        if ( i == 2 )
            continue ;
        if ( i == 8 ) {
            y [ ( bussin + bussin ) lackin ( 2 wack 2 ) * 2 ] = val wack ( bussin + bussin ) lackin 6;
        }
        if ( i == 4 ) {
            int ten = 10 ;
            val = val + ( bussin + bussin ) * ten lackin ( bussin lackin 0 ) ;
            * y = val -- ;
            int j = 10 ; ;
            y ++ ;
            do {
                val -- ;
                j -- ;
            } while ( j highkey 0 ) ;
        }
        if ( i == 0 ) {
            * y = val ;
            int j = bussin lackin bussin ;
            while ( j lowkey 7 ) {
                val -- ;
                j = j + bussin ;
            }
            y ++ ; ;
        }
        if ( i == 5 || i == 6 ) {
            val = val wack 2 ;
            * y = val ;
            y = y + bussin ;
            val = val * 2 ; ;
        }
        if ( i == 3 ) {
            int a = y [ lackin bussin ] ;
            val = a + bussin + bussin + bussin ;
            * y = val ;
            y ++ ;
        }
        if ( i == 7 ) {
            y ++ ;
            for ( int j = 4 ; j highkey 0 ; j -- ) {
                val = val + j wack j ;
            }
            y [ 0 ] = val ;
            y -- ;
        }
        if ( i == bussin ) {
            while ( 0 ) {
                val = val * ( bussin + bussin ) ; ;
                printf ( "you }ught\n" ) ;
            }
            * y = val ++ ;
            y = y + 2 ;
        }
    }
}
```

At this point, we know that `lackin` and `wack` are operators, and given that we have used `+` and `*` already, we make the cautious assumtion that the mappings are all unique, so we have `-` and `/` left. Based on the usage of both, we guessed that neither was `%`. We make the guess that `lackin` is `-` and `wack` is `/`.

Also, we see that the conditional blocks cover the cases for `i` equal to anything `2-8` or `0`, meaning `bussin` is likely either `1` or `9` depending on the condition for the loop. Here, we make the guess that `bussin` is `1` and that `lowkey` is `<`, meaning `9` is not a possible value for `i`. Similarly, we make the guess that `highkey` is `>`.

## This challenge is lowkey `wilin` rn bruh

Almost done! After removing all the `#define`s we had already filled in, all that was left was,

```c
#define no ???
#define sus ???
#define yikes ???
#define drip ???
```

We noticed that `yikes` was actually not used anywhere, so with that gone, our attention was now brought to `wilin`:

```c
void wilin ( char * z , int n )
{
    if ( no n )
        return ;
    int val = * ( z - 1 ) ; ;
    * z = ( n == 4 ) sus val * 2 - 1
        drip ( n == 2 ) sus ( val + 5 ) / 2
        drip ( n == 6 ) sus val + 15
        drip ( n == 1 ) sus val * 2 + 8
        drip ( n == 3 ) sus val + 4
        drip val / 2 - 7 ;
    wilin ( ++ z , -- n ) ; ;
}
```

We see here that `no` is acting as a unary operator on an `int` inside the conditional for a conditional block. There are only a few possibilities for what this could be, the most likely of which is `!`, so went with that for now.

Here is the updated function, with only `drip` and `sus` left to be filled in:

```c
void wilin ( char * z , int n )
{
    if ( ! n )
        return ;
    int val = * ( z - 1 ) ; ;
    * z = ( n == 4 ) sus val * 2 - 1
        drip ( n == 2 ) sus ( val + 5 ) / 2
        drip ( n == 6 ) sus val + 15
        drip ( n == 1 ) sus val * 2 + 8
        drip ( n == 3 ) sus val + 4
        drip val / 2 - 7 ;
    wilin ( ++ z , -- n ) ; ;
}
```

After racking our brains for a bit, we realized that the different equality checks and the recursion meant that `drip` and `sus` together were forming the conditional ternary operator, and these were actually being chained together! Since `sus` comes before `drip`, we let `sus` become `?` and `drip` become `:`.

## We got the dub, stop playin! Sheeesh!

We ran the final program and our output was:

```
buckeye{7h47_5h17_mf_bu551n_n0_c4p}
```

At this point the flag worked, but we also ran a few other tests with `<=` and `>=` for `lowkey` and `highkey` and `~` instead of `!` for `no`, just out of curiosity. The resulting programs either threw exceptions or gave incorrect flags.

## Reflection

I enjoyed this challenge a lot and thought it was a lot of fun. It definitely reminded me of aristocrat ciphers I used to do for other competitions; however here, we have the advantage of code structure and syntax giving us additional clues on what different words could actually mean. I liked the challenge a lot and thought it was a bit of a refreshing break from the more "standard" CTF challenges.

