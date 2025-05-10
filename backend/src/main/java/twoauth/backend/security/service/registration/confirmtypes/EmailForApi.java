package twoauth.backend.security.service.registration.confirmtypes;

import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

public final class EmailForApi extends JwtsHS512Token
{
    private final JavaMailSender mailSender;
    private final String userEmail;

    public EmailForApi(final JavaMailSender mailSender, final String userEmail) {
        super();
        this.mailSender = mailSender;
        this.userEmail = userEmail;
    }

    @Override
    public boolean sendConfirmationRequest()
    {
        System.out.printf("EmailForApi: %s%n", uniqueSecureToken);

        final SimpleMailMessage emailMessage = new SimpleMailMessage();
        emailMessage.setTo(userEmail);
        emailMessage.setSubject("Confirm Registration");
        emailMessage.setText(String.format("Insert this registration token in the next login: %s", uniqueSecureToken));

        try {
            mailSender.send(emailMessage);
        }
        catch (MailException e) {
            System.err.printf("EmailForApi JavaMailSender.send: %s - %s%n", userEmail, e.getMessage());
            return false;
        }
        System.out.printf("Email sent: %s%n", emailMessage);

        return true;
    }

    @Override
    public String toString() {
        return "EmailForApi{" +
                "userEmail='" + userEmail + '\'' +
                ", uniqueSecureToken='" + uniqueSecureToken + '\'' +
                '}';
    }
}
