---
title: Oblivionaire Online (OO) project code
---

# CITS3007 Project - Group 1

Group members:
- Sia J-Ern (24371251)
- Max Cutlyp (23368261)
- Daniel Le (23625105)
- Punit Patil (23905593)
- James Rimmer (22915304)

## Quick start

```shell
$ make install-dependencies
$ make test  # run unit tests
$ make fuzz  # begin fuzzing
```

## Automated tests

Run `make test` to build and run libcheck tests.

To add a test case, create one and add it to the test suite in `tests/check_accounts.c`.
You can do this with the macros from the `check` library:

```
START_TEST (your_test_name) {
    // your test code here...
}
END_TEST
```

Then add it to the test suite:

```
Suite *account_suite(void) {
    ...
    tcase_add_test(tc_core, your_test_name);
    ...
}
```

For more information, see the [libcheck docs](https://libcheck.github.io/check/doc/check_html/check_3.html).

## Installing and configuring libraries

You will almost certainly need to make use of external libraries to complete the project.
There are two files you will need to edit so that the Makefile can find the libraries you
need:

- `apt-packages.txt`: this file should contain a list of Ubuntu packages that are required
  to build your project, and need to be **installed** using `apt-get`. Each line should
  contain the name of one package. You can find the names of packages using `apt-cache search
  <package-substring>`, or by searching online. You can also use `apt-cache show
  <package-name>` to find out more about a particular package.

  Running

  ```
  $ make install-dependencies
  ```

  will install all the packages listed in `apt-packages.txt`. It does not compile or link
  your project.

- `libraries.txt`: this file should contain a list of libraries that GCC needs to **link
  against**. Each line should contain the name of one library. The name of a library is
  typically similar to the name of the Ubuntu package it is contained in, but not always. You
  can find the names of libraries using `pkg-config --list-all`.

  Once you have put a library name in `libraries.txt`, the Makefile will use that to
  automatically work out the correct compiler and linker
  options for the libraries you've specified -- so running `make all` or similar
  should link them correctly.
  (But this won't *install* them; you need to run `make install-dependencies` for that.)

<!--
  vim: tw=92 :
-->
