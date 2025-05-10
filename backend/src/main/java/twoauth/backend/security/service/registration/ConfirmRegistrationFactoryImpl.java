package twoauth.backend.security.service.registration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import twoauth.backend.security.service.registration.confirmtypes.*;

@Service
public class ConfirmRegistrationFactoryImpl implements ConfirmRegistrationFactory
{
    private final JavaMailSender mailSender;
    private final ConfirmType confirmType;

    public ConfirmRegistrationFactoryImpl(
            @Value("${2Auth.registration-confirmation:TEST_FOR_API}") String confirmType,
            JavaMailSender mailSender
    ) {
        this.mailSender = mailSender;
        this.confirmType = ConfirmType.valueOf(confirmType);
    }

    @Override
    public ConfirmRegistration newConfirmRegistration(final String userEmail) {
        return switch (confirmType) {
            case NONE -> new None();
            case EMAIL_FOR_FRONTEND -> new EmailForFrontend(mailSender, userEmail);
            case EMAIL_FOR_API -> new EmailForApi(mailSender, userEmail);
            case TEST_FOR_FRONTEND -> new TestForFrontend();
            case TEST_FOR_API -> new TestForApi();
        };
    }
}
