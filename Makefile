.PHONY: cover

BIN_PATH:=node_modules/.bin/

all:	wallet-client.min.js

clean:
	rm wallet-client.js
	rm wallet-client.min.js

wallet-client.js: index.js lib/*.js
	${BIN_PATH}browserify $< > $@

wallet-client.min.js: wallet-client.js
	uglify  -s $<  -o $@

cover:
	./node_modules/.bin/istanbul cover ./node_modules/.bin/_mocha -- --reporter spec test
