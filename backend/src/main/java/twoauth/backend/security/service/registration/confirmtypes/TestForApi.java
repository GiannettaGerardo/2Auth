package twoauth.backend.security.service.registration.confirmtypes;

public final class TestForApi extends JwtsHS512Token
{
    public TestForApi() {
        super();
    }

    @Override
    public boolean sendConfirmationRequest() {
        System.out.printf("TestForApi: %s%n", this.uniqueSecureToken);
        return true;
    }

    @Override
    public String toString() {
        return "TestForApi{" +
                "uniqueSecureToken='" + uniqueSecureToken + '\'' +
                '}';
    }
}
