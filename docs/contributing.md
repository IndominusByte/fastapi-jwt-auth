## Sharing feedback

This project is still quite new and therefore having your feedback will really help to
prioritize relevant feature developments :rocket:. If you want to contribute thankss a lot :smile:, you can
open an <a href="https://github.com/IndominusByte/fastapi-jwt-auth/issues/new" target="_blank">issue</a> on Github.

## Developing

If you already cloned the repository and you know that you need to deep dive in the code, here are some guidelines to set up your environment.

### Virtual environment with venv

You can create a virtual environment in a directory using Python's `venv` module:

```bash
$ python3 -m venv env
```

That will create a directory `./env/` with the Python binaries and then you will be able to install packages for that isolated environment.

### Activate the environment

```bash
$ source ./env/bin/activate
```

To check it worked, use:

```bash
$ which pip

some/directory/fastapi-jwt-auth/env/bin/pip
```

If it shows the pip binary at env/bin/pip then it worked. 🎉

!!! tip
    Every time you install a new package with `pip` under that environment, activate the environment again.
    This makes sure that if you use a terminal program installed by that package (like `flit`),
    you use the one from your local environment and not any other that could be installed globally.

### Flit

FastAPI JWT Auth uses <a href="https://flit.readthedocs.io/en/latest/index.html" class="external-link" target="_blank">Flit</a> to build, package and publish the project.

After activating the environment as described above, install `flit`:

```bash
$ pip install flit
```

Now re-activate the environment to make sure you are using the `flit` you just installed (and not a global one).

And now use `flit` to install the development dependencies:

```bash
$ flit install --deps develop --symlink
```

It will install all the dependencies and your local FastAPI JWT Auth in your local environment.

**Using your local FastAPI JWT Auth**

If you create a Python file that imports and use FastAPI JWT Auth, and run it with the Python from your local environment, it will use your localFastAPI JWT Auth source code.

And if you update that local FastAPI JWT Auth source code, as it is installed with `--symlink`, when you run that Python file again, it will use the fresh version of FastAPI JWT Auth you just edited.

That way, you don't have to "install" your local version to be able to test every change.

## Docs

The documentation uses <a href="https://www.mkdocs.org/" class="external-link" target="_blank">MkDocs</a>.

All the documentation is in Markdown format in the directory `./docs`.

Many of the sections in  the User Guide have blocks of code.

In fact, those blocks of code are not written inside the Markdown, they are Python files in the `./examples/` directory.

And those Python files are included/injected in the documentation when generating the site.

### Docs for tests

Most of the tests actually run against the example source files in the documentation.

This helps making sure that:

* The documentation is up to date.
* The documentation examples can be run as is.
* Most of the features are covered by the documentation, ensured by test coverage.

During local development, there is a script that builds the site and checks for any changes, live-reloading:

```bash
$ bash scripts/docs-live.sh
```

It will serve the documentation on `http://0.0.0.0:5000`.

That way, you can edit the documentation/source files and see the changes live.

## Tests

There is a script that you can run locally to test all the code and generate coverage reports in HTML:

```bash
$ bash scripts/tests.sh
```

This command generates a directory `./htmlcov/`, if you open the file `./htmlcov/index.html` in your browser, you can explore interactively the regions of code that are covered by the tests, and notice if there is any region missing.
