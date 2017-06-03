==== This is NOT my code, I am working from a base of code written by Gary Kertopermono who ported their PHP code from a C version originally written by Ryan Holtz (@TheMogMiner) ====

The website is available here: http://retrocheater.multiverseworks.com/acuc2/index.php?mod=generator

What I am doing with the code is extending it to automatically find optimal town and player names
which will minimize the travel distance of all the codes needed for Animal Crossing 100%

I'm going to be using the codes listed in this route:
https://pastebin.com/kVpwVcep
as well as this addendum:
http://pastebin.com/TMyMNJ5P

I'll put those files in this repository for safe keeping as well.

TODO:
A lot of these characters look like they can't be input ingame, need to check what can actually be used. Probably with a memory viewer.
This would be much better if it just wrote out all the stats to a CSV, so I could analyze them post facto rather than assuming everything works perfectly
Figure out how "generate multiple codes" works on the website and backport over here so I can get even more search space
Parallelize with OpenMP (or maybe OpenMPI, I did like OpenMPI better)


Original readme below:


Animal Crossing Code Generator v1.7
    by MooglyGuy / UltraMoogleMan

This should be able to generate codes for most of the items in
Animal Crossing. So far the known offenders for which you
absolutely cannot generate universal codes are as follows:

Insects
Fish
Legend of Zelda
Super Mario Brothers
Ice Climbers
Mario Brothers
"Glitch" items in the GSCentral code list - Fully-grown trees,
    sign boards, and so on.
Probably some more items that I can't be bothered to find out.

Please note that you can NOT generate universal codes for the
following items, but you CAN create NES Contest Codes for them:

Baseball
Clu Clu Land D
Donkey Kong 3
Donkey Kong Jr.
Punchout
Soccer
Probably a couple more that I've forgotten in the past month.

To find out the item digits for the item for which you want to
generate a code, download the list of item digits off of my
website.

USAGE:
./codegen [U, P, or N] [Player Name] [Town Name] [Item Number IN LOWERCASE]

IF A CODE DOES NOT WORK FOR YOU:
    1. Double-check every character to make sure that you entered
       them in correctly.
    2. If you're 100% sure that you've entered the code correctly,
       email me at the address listed below, but MAKE SURE to
       include the following information:
           A. What kind of code you are trying to generate:
              Universal, NES, or Player-to-Player.
           B. The destination player name, if applicable.
           C. The destination town name, if applicable.
           D. The item number.
       If you do not include all of the above information, I will
       not respond to your email. I'm tired of people just telling
       me that "it doesn't work" without including any other info.
       In case nobody has guessed by now, I'm not a psychic, so
       don't act like I am.

You can contact me at zrah2@imail.etsu.edu if necessary.

CHANGELOG:
	v1.7: Bugfix.
            I figured it was high time that I released a fixed
                version of the source code, so here it is.
	v1.6: Source release.
	    It's been six months in coming, but I've finally
	        cleaned up the code enough to release it
	        publicly. Enjoy.
        v1.5: Fifth public release.
            Hopefully I managed to fix a nasty bug that was
                affecting the NES Contest Codes. The three
                test cases that I used, one of which did not
                previously work, now work.
        v1.4: Fourth public release.
            Nothing readily apparent to anybody using the program
                should be changed, since all I did was rework the
                encryption routines so that they can be more
                easily understood once I release the source code.
        v1.3: Third public release.
            Imagine that! Fixed more bugs!
        v1.2: Second public release.
            Fixed a nasty bug in the RSA encryption, this should
                allow you to generate code for almost all of the
                normally-obtainable items. This bug seemed to be
                pseudo-random, so if you couldn't generate a code
                before, try it again.
            Added player-to-player code generation in case you
                want to generate a code for a friend and you only
                want him or her to be able to use it.
            Added NES contest code generation for DK3, DK Junior,
                Soccer, Clu Clu Land D, and Punchout.
            Added a spiffy user interface.
        v1.1: Private build only.
        v1.0: Initial release.
            Everything could be considered changed!
