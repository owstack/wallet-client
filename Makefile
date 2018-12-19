.PHONY:	cover	

BIN_PATH:=node_modules/.bin/

all:	cover	wallet-client.js

clean:
	rm wallet-client.js

wallet-client.js: index.js lib/*
	${BIN_PATH}browserify $< > $@

cover:
	./node_modules/.bin/istanbul cover ./${BIN_PATH}/_mocha -- --reporter spec test
