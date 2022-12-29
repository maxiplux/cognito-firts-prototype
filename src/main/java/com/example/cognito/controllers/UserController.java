package com.example.cognito.controllers;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.services.cognitoidp.model.*;
import com.example.cognito.config.aws.AwsConfig;
import com.example.cognito.errors.CustomException;
import com.example.cognito.models.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;

@RestController
@RequestMapping(path = "/api/users")
@Slf4j
public class UserController {

    @Autowired
    private AwsConfig awsConfig;
    @Autowired
    private AWSCognitoIdentityProvider cognitoClient;

    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;
    @Value(value = "${aws.cognito.clientId}")
    private String clientId;



    @PostMapping(path = "/sign-up")
    public void signUp(@RequestBody UserSignUpRequest userSignUpRequest) {

        try {

            AttributeType emailAttr =
                    new AttributeType().withName("email").withValue(userSignUpRequest.getEmail());
            AttributeType emailVerifiedAttr =
                    new AttributeType().withName("email_verified").withValue("true");

            AdminCreateUserRequest userRequest = new AdminCreateUserRequest()
                    .withUserPoolId(userPoolId).withUsername(userSignUpRequest.getUsername())
                    .withTemporaryPassword(userSignUpRequest.getPassword())
                    .withUserAttributes(emailAttr, emailVerifiedAttr)
                    .withMessageAction(MessageActionType.SUPPRESS)
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(userRequest);

            log.debug("User " + createUserResult.getUser().getUsername()
                    + " is created. Status: " + createUserResult.getUser().getUserStatus());

            // Disable force change password during first login
            AdminSetUserPasswordRequest adminSetUserPasswordRequest =
                    new AdminSetUserPasswordRequest().withUsername(userSignUpRequest.getUsername())
                            .withUserPoolId(userPoolId)
                            .withPassword(userSignUpRequest.getPassword()).withPermanent(true);

            cognitoClient.adminSetUserPassword(adminSetUserPasswordRequest);

        } catch (AWSCognitoIdentityProviderException e) {
            log.error(e.getErrorMessage());
        } catch (Exception e) {
            log.error("Setting user password" + e.getMessage());
        }
    }






    @PostMapping(path = "/sign-in")
    public @ResponseBody
    UserSignInResponse signIn(@RequestBody UserSignInRequest userSignInRequest) {

        UserSignInResponse userSignInResponse = new UserSignInResponse();

        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", userSignInRequest.getUsername());
        authParams.put("PASSWORD", userSignInRequest.getPassword());

        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH).withClientId(clientId)
                .withUserPoolId(userPoolId).withAuthParameters(authParams);

        try {
            AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);

            AuthenticationResultType authenticationResult = null;

            if (result.getChallengeName() != null && !result.getChallengeName().isEmpty()) {

                log.info("signIn Challenge Name is " + result.getChallengeName());

                if (result.getChallengeName().contentEquals("NEW_PASSWORD_REQUIRED")) {
                    if (userSignInRequest.getPassword() == null) {
                        log.error("User must change password " + result.getChallengeName());
                        throw new CustomException(
                                "User must change password " + result.getChallengeName());


                    } else {

                        final Map<String, String> challengeResponses = new HashMap<>();
                        challengeResponses.put("USERNAME", userSignInRequest.getUsername());
                        challengeResponses.put("PASSWORD", userSignInRequest.getPassword());
                        // add new password
                        challengeResponses.put("NEW_PASSWORD", userSignInRequest.getNewPassword());

                        final AdminRespondToAuthChallengeRequest request =
                                new AdminRespondToAuthChallengeRequest()
                                        .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                                        .withChallengeResponses(challengeResponses)
                                        .withClientId(clientId).withUserPoolId(userPoolId)
                                        .withSession(result.getSession());

                        AdminRespondToAuthChallengeResult resultChallenge =
                                cognitoClient.adminRespondToAuthChallenge(request);
                        authenticationResult = resultChallenge.getAuthenticationResult();

                        userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                        userSignInResponse.setIdToken(authenticationResult.getIdToken());
                        userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                        userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                        userSignInResponse.setTokenType(authenticationResult.getTokenType());
                    }

                } else {
                    log.error("signIn User has other challenge " + result.getChallengeName());
                    throw new CustomException(
                            "User has other challenge " + result.getChallengeName());
                }
            } else {

                log.info("signIn User has no challenge");
                authenticationResult = result.getAuthenticationResult();

                userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                userSignInResponse.setIdToken(authenticationResult.getIdToken());
                userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                userSignInResponse.setTokenType(authenticationResult.getTokenType());
            }

        } catch (InvalidParameterException e) {
            log.error("signIn InvalidParameterException {}",e.getMessage());
            throw new CustomException(e.getErrorMessage());
        } catch (Exception e) {
            log.error("signIn Exception {}", e.getMessage());
            throw new CustomException(e.getMessage());
        }
     //   cognitoClient.shutdown();
        return userSignInResponse;

    }
    @Operation(summary = "My endpoint", security = @SecurityRequirement(name = "bearerAuth"))

    private Claims getAllClaimsFromToken(String token) {
        Claims claims;
        try {
            //.setSigningKey(SECRET)
            claims = Jwts.parser()

                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.error("Could not get all claims Token from passed token {}",e.getMessage());
            claims = null;
        }
        return claims;
    }



//    public AWSCognitoIdentityProvider getAmazonCognitoIdentityClient() {
//        ClasspathPropertiesFileCredentialsProvider propertiesFileCredentialsProvider =
//                new ClasspathPropertiesFileCredentialsProvider();
//
//
//        return AWSCognitoIdentityProviderClientBuilder.standard()
//                .withCredentials(propertiesFileCredentialsProvider)
//                .withRegion(awsConfig.getCognito().getRegion())
//                .build();
//
//    }

    public UserResponse getUserInfo(String username) {


        AdminGetUserRequest userRequest = new AdminGetUserRequest()
                .withUsername(username)
                .withUserPoolId(awsConfig.getCognito().getUserPoolId());


        AdminGetUserResult userResult = cognitoClient.adminGetUser(userRequest);

        UserResponse userResponse = new UserResponse();
        userResponse.setUsername(userResult.getUsername());
        userResponse.setUserStatus(userResult.getUserStatus());
        userResponse.setCreationDate(userResult.getUserCreateDate());
        userResponse.setLastModifiedDate(userResult.getUserLastModifiedDate());

//        List userAttributes = userResult.getUserAttributes();
//        for(AttributeTypeattribute: userAttributes) {
//            if(attribute.getName().equals("custom:companyName")) {
//                userResponse.setCompanyName(attribute.getValue());
//            }else if(attribute.getName().equals("custom:companyPosition")) {
//                userResponse.setCompanyPosition(attribute.getValue());
//            }else if(attribute.getName().equals("email")) {
//                userResponse.setEmail(attribute.getValue());
//            }
//        }


        return userResponse;

    }
    //@PreAuthorize("hasRole('ROLE_USER')")
    @PreAuthorize("hasRole('ROLE_USER')")

    //@PreAuthorize("isAuthenticated()")
    @GetMapping(path = "/detail")
    public @ResponseBody  UserResponse getUserDetail(Principal principal) {
        Authentication token = SecurityContextHolder.getContext().getAuthentication();



        token.getAuthorities().forEach(clientId-> log.debug("Current log {}",clientId.getAuthority()));
        //Claims claims =getAllClaimsFromToken( token.getCredentials().toString());
        return  getUserInfo("maxiplux");
    }
}
