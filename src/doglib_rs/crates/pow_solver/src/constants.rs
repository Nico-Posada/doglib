// max keyspace we will bruteforce (charset)**MAX_SUFFIX_LEN
// the higher the number, the more likely we find a valid candidate,
// but the less likely we can use GPU (to fit inside a single SHA block we must ensure
//  that (len(prefix)%64)+len(suffix) < 64), so the bigger the suffix the less likely that is true )
// 15 is a safe bet, the most restricted charset is numeric (0-9), 
//  so this should work for up to log2(10**15) == 49 bit numeric POWs (and no issue for any others)
pub const MAX_SUFFIX_LEN: usize = 15;