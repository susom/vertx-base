# Vert.x Base Library

Vert.x Base is a Java library providing common functionality for writing Vert.x web applications in a safe and maintainable way. It includes security, authentication, configuration management, and database integration utilities.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and Setup
- Java 17 is required (project uses Java 17 target)
- Maven 3.9+ is required for building
- Git for version control

### Building and Testing
- Bootstrap and compile the project:
  - `mvn clean compile` -- takes ~10 seconds to complete. NEVER CANCEL. Set timeout to 30+ seconds.
- Run tests:
  - `mvn test` -- takes ~9 seconds. NEVER CANCEL. Set timeout to 30+ seconds.
- Full verification with packaging and documentation:
  - `mvn verify` -- takes ~25 seconds to complete. NEVER CANCEL. Set timeout to 60+ seconds.

### Running Sample Applications
- **ALWAYS** run `mvn test-compile` first to ensure test classes are compiled.
- Run the main sample application:
  - `mvn test-compile exec:java -Dexec.mainClass="com.github.susom.vertx.base.test.SampleMain" -Dexec.classpathScope=test`
  - Starts a web server on http://localhost:8888
  - Includes authentication flow and database integration
  - Uses HSQLDB in-memory database for testing
- Run the email authentication sample:
  - `mvn test-compile exec:java -Dexec.mainClass="com.github.susom.vertx.base.test.EmailLoginSample" -Dexec.classpathScope=test`
  - Starts on http://localhost:8878 (different port)
  - Demonstrates email-based authentication flow
- Run the password-only sample:
  - `mvn test-compile exec:java -Dexec.mainClass="com.github.susom.vertx.base.test.PasswordOnlySample" -Dexec.classpathScope=test`
  - Starts on http://localhost:8877 (different port)
  - Demonstrates simple password-based authentication

## Validation

### Manual Testing Scenarios
- **ALWAYS** manually validate any new code by running at least one sample application after making changes.
- Test the main application flow:
  1. Start SampleMain application
  2. Access http://localhost:8888/app (should return 401 with authentication redirect)
  3. Verify the application responds properly (not 500 errors)
  4. Stop the application with Ctrl+C
- Test compilation after code changes:
  1. Run `mvn clean compile` to ensure no compilation errors
  2. Run `mvn test` to ensure tests pass
  3. If adding new functionality, run `mvn verify` for full validation

### Common Validation Commands
- Always run `mvn verify` before finalizing changes to ensure packaging works correctly.
- Check for deprecated API usage warnings during compilation.
- The build may show warnings about deprecated Security Manager usage - this is expected.

## Important Project Information

### Dependency Resolution Issue
- **CRITICAL**: The project depends on `com.github.susom:database:5.0-github-build-257` which is not available in public repositories.
- **SYMPTOM**: Build fails with "Could not transfer artifact com.github.susom:database:pom:5.0-github-build-257" and hostname resolution errors.
- **WORKAROUND**: Temporarily modify the version to `4.0` in pom.xml to test changes: `<version>4.0</version>`
- **NEVER** commit the modified pom.xml with version 4.0 - restore the original version before committing.
- This is a known limitation when working outside the Stanford infrastructure.

### Key Project Structure
```
src/
├── main/java/com/github/susom/vertx/base/
│   ├── VertxBase.java                 # Main utility class with MDC support and setup methods
│   ├── SecurityImpl.java              # Core security and authentication implementation
│   ├── Valid.java                     # Input validation utilities
│   ├── *Authenticator.java           # Various authentication implementations (SAML, OAuth, etc.)
│   └── *Handler.java                 # HTTP request handlers and utilities
├── test/java/com/github/susom/vertx/base/test/
│   ├── SampleMain.java               # Main sample application with SAML authentication
│   ├── EmailLoginSample.java         # Email-based authentication sample
│   ├── PasswordOnlySample.java       # Simple password authentication sample
│   └── ClientTest.java               # Tests for MDC preservation in HTTP client calls
└── main/resources/static/            # Static web assets (CSS, JS, HTML)
```

### Technology Stack
- **Framework**: Vert.x 3.9.16 (reactive web framework)
- **Java Version**: 17 (compilation target)
- **Build Tool**: Maven 3.9+
- **Testing**: JUnit 4.13.2, Vert.x Unit, HSQLDB 2.7.1
- **Security**: SAML, OAuth2, JWT support
- **Database**: Supports multiple databases via susom/database library

### Configuration
- Sample applications use HSQLDB file database: `jdbc:hsqldb:file:target/hsqldb;shutdown=true`
- Default server runs on http://localhost:8888
- Authentication is configured via `Config.from().value()` chain in sample applications
- SAML configuration requires keystore files in `conf/` directory (not included in repo)

## Common Tasks

### Adding New Features
1. **ALWAYS** test your changes by running at least one sample application
2. Add appropriate validation using the `Valid` class utilities
3. Follow the existing patterns for authentication and security
4. Use `VertxBase.mdc()` wrapper for async operations to preserve logging context
5. Run `mvn verify` to ensure packaging and documentation generation works

### Debugging Issues
- Enable debug logging by modifying `src/test/resources/log4j.xml`
- Database operations are logged with timing information
- Sample applications log to console with timestamps
- Use `curl -I http://localhost:8888/app` to test authentication flows

### Working with Authentication
- The library supports multiple authentication methods: SAML, OAuth2, Email login, Password-only
- `SecurityImpl` class provides the main authentication router setup
- Use `security.authenticatedRouter("/path")` to create protected routes
- Sample applications demonstrate different authentication configurations

### Database Integration
- Database functionality depends on the `com.github.susom/database` library
- Uses connection pooling via HikariCP
- HSQLDB is used for testing and development
- Database operations preserve MDC context in async environments

## Time Expectations
- **Compilation**: ~10 seconds - NEVER CANCEL
- **Tests**: ~9 seconds - NEVER CANCEL  
- **Full Verification**: ~25 seconds - NEVER CANCEL
- **Application Startup**: ~2-3 seconds for sample applications
- **First Build**: May take longer due to dependency downloads (~2-5 minutes)

## CI/CD Information
- GitHub Actions workflow: `.github/workflows/vertx-base.yaml`
- Travis CI configuration: `.travis.yml`
- Deploys to Google Artifact Registry on master branch pushes
- Uses Java 17 for all builds
- Includes SonarCloud analysis for code quality