## Sharing feedback

This project is still quite new and therefore having your feedback will really help to
prioritize relevant feature developments :rocket:. If you want to contribute thankss a lot :smile:, you can
open an <a href="https://github.com/IndominusByte/fastapi-jwt-auth/issues/new">issue</a> on Github.

## Developing

If you already cloned the repository and you know that you need to deep dive in the code, here are some guidelines to set up your environment.

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
bash scripts/tests.sh
```

This command generates a directory `./htmlcov/`, if you open the file `./htmlcov/index.html` in your browser, you can explore interactively the regions of code that are covered by the tests, and notice if there is any region missing.
