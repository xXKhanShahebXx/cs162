# -*- perl -*-
use strict;
use warnings;
use tests::tests;

check_expected ([<<'EOF']);
(seek-normal) begin
(seek-normal) create seek.dat
(seek-normal) open seek.dat
(seek-normal) open seek.dat again
(seek-normal) seek test passed
(seek-normal) end
seek-normal: exit(0)
EOF

pass;
