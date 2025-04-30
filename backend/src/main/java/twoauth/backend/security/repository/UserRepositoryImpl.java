package twoauth.backend.security.repository;

import twoauth.backend.exception.InvalidDbEntityException;
import twoauth.backend.security.Validator;
import twoauth.backend.security.model.User;
import twoauth.backend.security.model.UserDetailsImpl;
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
public class UserRepositoryImpl implements UserRepository
{
    private final MongoTemplate mongoTemplate;

    @Override
    public Optional<UserDetails> findUserDetailsById(final String email)
    {
        final var user = mongoTemplate.findById(email, User.class, UserRepository.TABLE);
        if (user != null) {
            final var userDetails = new UserDetailsImpl(
                    user.getEmail(),
                    user.getPassword(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.getCreation(),
                    user.getLastUpdate(),
                    user.getPermissions()
            );
            Optional<UserDetails> userDetailsOpt = Optional.of(userDetails);
            user.eraseCredentials();

            String errorMessage;
            if ((errorMessage = Validator.validateUserDetailsImpl(userDetails)) != null)
                throw new InvalidDbEntityException(errorMessage);

            return userDetailsOpt;
        }
        return Optional.empty();
    }

    @Override
    public Optional<User.NoPasswordDto> findById(final String email)
    {
        final var user = mongoTemplate.findById(email, User.NoPasswordDto.class, UserRepository.TABLE);
        if (user != null) {
            String errorMessage;
            if ((errorMessage = Validator.validateUserNoPassword(user)) != null)
                throw new InvalidDbEntityException(errorMessage);

            return Optional.of(user);
        }
        return Optional.empty();
    }

    @Override
    public boolean save(final User user)
    {
        var now = new Date();
        user.setCreation(now);
        user.setLastUpdate(now);
        try {
            mongoTemplate.insert(user, UserRepository.TABLE);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public boolean optimisticLockUpdate(final User.NoPasswordDto user)
    {
        final var query = new Query(Criteria.where("_id").is(user.email())
                .and("lastUpdate").is(user.lastUpdate()));

        final var update = new Update();
        update.set("firstName", user.firstName());
        update.set("lastName", user.lastName());
        update.set("lastUpdate", new Date());

        final var options = new FindAndModifyOptions().returnNew(false).upsert(false);

        mongoTemplate.findAndModify(query, update, options, User.class, UserRepository.TABLE);
        return true;
    }

    @Override
    public boolean delete(final String email)
    {
        final var query = new Query(Criteria.where("_id").is(email));
        final DeleteResult dr = mongoTemplate.remove(query, User.class, UserRepository.TABLE);
        return dr.getDeletedCount() == 1;
    }
}
