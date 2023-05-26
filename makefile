#variables
PYTHON           := python3
PIP              := pip3
#python main files
SERVER_MAIN_FILE := server.py
CLIENT_MAIN_FILE := client.py
#directories
SERVER_DIR       := server
CLIENT_DIR       := client
TEST_DIR         := tests

runServer:
	$(PYTHON) $(SERVER_DIR)/$(SERVER_MAIN_FILE)

runClient:
	$(PYTHON) $(CLIENT_DIR)/$(CLIENT_MAIN_FILE)

setup:
	$(PIP) install -r requirements.txt

testServer:
	$(PYTHON) -m unittest $(SERVER_DIR)/$(TEST_DIR)/test_$(tf).py > /dev/null

testServerPrint:
	$(PYTHON) -m unittest $(SERVER_DIR)/$(TEST_DIR)/test_$(tf).py

testServerAll:
	$(PYTHON) -m unittest $(SERVER_DIR)/$(TEST_DIR)/test_* > /dev/null

testServerAllPrint:
	$(PYTHON) -m unittest $(SERVER_DIR)/$(TEST_DIR)/test_*
	
testClient:
	$(PYTHON) -m unittest $(CLIENT_DIR)/$(TEST_DIR)/test_$(tf).py > /dev/null

testClientPrint:
	$(PYTHON) -m unittest $(CLIENT_DIR)/$(TEST_DIR)/test_$(tf).py

testClientAll:
	$(PYTHON) -m unittest $(CLIENT_DIR)/$(TEST_DIR)/test_* > /dev/null

testClientAllPrint:
	$(PYTHON) -m unittest $(CLIENT_DIR)/$(TEST_DIR)/test_*

.PHONY: runServer runClient setup testServer testServerPrint testServerAll testServerAllPrint testClient testClientPrint testClientAll testClientAllPrint