# bc-fips-utils
Utility code for working with bouncy castle constructs

In order to run IDTokenValidation.java, from root, `mvn clean install` then `mvn exec:java -Dexec.mainClass=org.IDTokenValidation` also from root. This will run the command line output from maven. All logic in `src/main/java/org/IDTokenValidation.java`. 

You can also just open the project in IntelliJ, `mvn clean install`, then right click on IDTokenValidation -> Run IdToken...main()
