package twoauth.apigateway.securityconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationTests
{
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void getJwtBase64PayloadSubstring_ReturnsPayload_WhenJwtIsValid()
    {
        final String header = "NXIEU24NTO";
        final String payload = "RJVNI3V5V";
        final String signature = "WINCIU4";

        final String returnedPayload = JwtAuthentication.getJwtBase64PayloadSubstring(
                String.format("%s.%s.%s", header, payload, signature)
        );

        assertEquals(payload, returnedPayload);
    }

    @Test
    void getJwtBase64PayloadSubstring_ReturnsPayload_WhenTwoDotsAreFoundButOnlyPayloadIsPresent()
    {
        final String payload = "RJVNI3V5V";

        final String returnedPayload = JwtAuthentication.getJwtBase64PayloadSubstring(
                String.format(".%s.", payload)
        );

        assertEquals(payload, returnedPayload);
    }

    @Test
    void getJwtBase64PayloadSubstring_ReturnsIllegalArgumentException_WhenJwtIsEmpty()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.getJwtBase64PayloadSubstring("");
        });
    }

    @Test
    void getJwtBase64PayloadSubstring_ReturnsIllegalArgumentException_WhenNotDotsAreFound()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.getJwtBase64PayloadSubstring("NXIEU24NTORJVNI3V5V");
        });
    }

    @Test
    void getJwtBase64PayloadSubstring_ReturnsIllegalArgumentException_WhenOnlyOneDotIsFound()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.getJwtBase64PayloadSubstring("NXIEU24NTO.RJVNI3V5V");
        });
    }

    @Test
    void getJwtBase64PayloadSubstring_ReturnsIllegalArgumentException_WhenTwoDotsAreSubsequent()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.getJwtBase64PayloadSubstring("..");
        });
    }

    @Test
    void extractSubjectFromPayload_ReturnsSubject_WhenInputIsACorrectJsonWithSubAsString()
    {
        final String subject = "test";
        final String subjectJson = "{\"sub\": \""+ subject +"\"}";

        final String subjectReturned = JwtAuthentication.extractSubjectFromPayload(subjectJson, objectMapper);

        assertEquals(subject, subjectReturned);
    }

    @Test
    void extractSubjectFromPayload_ReturnsIllegalArgumentException_WhenJsonDoesNotContainSub()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.extractSubjectFromPayload("{}", objectMapper);
        });
    }

    @Test
    void extractSubjectFromPayload_ReturnsIllegalArgumentException_WhenSubIsNotAStringButAnInteger()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.extractSubjectFromPayload("{\"sub\": 1}", objectMapper);
        });
    }

    @Test
    void extractSubjectFromPayload_ReturnsIllegalArgumentException_WhenSubIsNotAStringButAnObject()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.extractSubjectFromPayload("{\"sub\": {}}", objectMapper);
        });
    }

    @Test
    void extractSubjectFromPayload_ReturnsIllegalArgumentException_WhenInputIsNotAValidJson()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            JwtAuthentication.extractSubjectFromPayload("test", objectMapper);
        });
    }

    @Test
    void newJwtAuthentication_ReturnsIllegalArgumentException_WhenJwtPayloadIsNotAValidBase64String()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            new JwtAuthentication("cjnrjvni3.c3n4icun3ijnf.ci3jni4", objectMapper);
        });
    }
}
