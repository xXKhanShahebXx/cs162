# -*- perl -*-
use strict;
use warnings;
use tests::tests;

check_expected ([<<'EOF']);
(tell-normal) begin
(tell-normal) create tell.dat
(tell-normal) open tell.dat
(tell-normal) open tell.dat again
(tell-normal) end
tell-normal: exit(0)
EOF

pass;
