LIBRARY SELFTESTS
=================

Simple crate for invoking the selftests for lib/ code. Library code is
complex, and will be load bearing in the future. Parts of it are also not widely
exercised and so can stay latent for a long time. This crate solves the problem
by letting us automatically invoke selftests for the library code.
