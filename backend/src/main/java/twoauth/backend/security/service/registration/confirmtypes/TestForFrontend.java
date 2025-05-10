package twoauth.backend.security.service.registration.confirmtypes;

public final class TestForFrontend extends JwtsHS512Token
{
    public TestForFrontend() {
        super();
    }

    @Override
    public boolean sendConfirmationRequest() {
        System.out.printf("TestForFrontend: %s%n", this.uniqueSecureToken);
        return true;
    }

    @Override
    public String toString() {
        return "TestForFrontend{" +
                "uniqueSecureToken='" + uniqueSecureToken + '\'' +
                '}';
    }
}
