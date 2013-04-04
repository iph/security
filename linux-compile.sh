rm -r -f bin/cs1653
javac -cp .:bcpkix-jdk15on-148.jar:bcprov-jdk15on-148.jar:commons-collections-3.2.1.jar -d bin src/cs1653/termproject/clients/*.java src/cs1653/termproject/servers/*.java src/cs1653/termproject/shared/*.java
