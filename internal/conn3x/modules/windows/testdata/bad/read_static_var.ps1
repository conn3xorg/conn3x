# expect: $t::Delete isn't on the list
param($A)
$t = [IO.File]
$t::Delete($A.a)
