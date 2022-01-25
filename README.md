This branch contains the source code for <https://www.pycrypto.org/>, including
copies of the releases and the mailing list archives.

To build this outside GitHub, install Ruby and [Bundler](https://bundler.io/)
and then do something like this:

```sh
bundle config set --local path vendor/bundle
bundle install
bundle exec jekyll serve
```
