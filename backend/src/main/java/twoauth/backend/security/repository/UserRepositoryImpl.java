package twoauth.backend.security.repository;

import twoauth.backend.exception.InvalidDbEntityException;
import twoauth.backend.security.Validator;
import twoauth.backend.security.model.User;
import com.mongodb.client.result.DeleteResult;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository, UserSecurityRepository
{
    private final MongoTemplate mongoTemplate;

    @Override
    public Optional<UserDetails> findUserDetailsById(final String email)
    {
        final var user = mongoTemplate.findById(email, User.class, UserSecurityRepository.TABLE);
        if (user != null) {
            String errorMessage;
            if ((errorMessage = Validator.validateUser(user)) != null)
                throw new InvalidDbEntityException(errorMessage);

            return Optional.of(user);
        }
        return Optional.empty();
    }

    @Override
    public Optional<User.SecureDto> findById(final String email)
    {
        final var user = mongoTemplate.findById(email, User.SecureDto.class, UserRepository.TABLE);
        if (user != null) {
            String errorMessage;
            if ((errorMessage = Validator.validateUserSecureDto(user)) != null)
                throw new InvalidDbEntityException(errorMessage);

            return Optional.of(user);
        }
        return Optional.empty();
    }

    @Override
    public boolean save(final User user)
    {
        try {
            return null != mongoTemplate.insert(user, UserSecurityRepository.TABLE);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            return false;
        }
    }

    @Override
    public boolean optimisticLockEnableUserAccount(final User user)
    {
        final var query = new Query(Criteria.where("_id").is(user.getEmail())
                .and("lastUpdate").is(user.getLastUpdate())
                .and("isActive").is(false)
                .and("activationToken").is(user.getActivationToken()));

        final var options = new FindAndModifyOptions().returnNew(false).upsert(false);

        final var update = new Update();
        update.set("isActive", true);
        update.set("activationToken", null);
        update.set("lastUpdate", new Date());

        try {
            return null != mongoTemplate.findAndModify(query, update, options, User.class, UserSecurityRepository.TABLE);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            return false;
        }
    }

    @Override
    public boolean optimisticLockUpdate(final User.SecureDto user)
    {
        final var query = new Query(Criteria.where("_id").is(user.email())
                .and("lastUpdate").is(user.lastUpdate()));

        final var options = new FindAndModifyOptions().returnNew(false).upsert(false);

        final var update = new Update();
        update.set("firstName", user.firstName());
        update.set("lastName", user.lastName());
        update.set("lastUpdate", new Date());

        try {
            return null != mongoTemplate.findAndModify(query, update, options, User.class, UserRepository.TABLE);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            return false;
        }
    }

    @Override
    public boolean delete(final String email)
    {
        final var query = new Query(Criteria.where("_id").is(email));
        final DeleteResult dr = mongoTemplate.remove(query, User.class, UserRepository.TABLE);
        return dr.getDeletedCount() == 1;
    }
}
