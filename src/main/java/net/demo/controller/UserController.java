package net.demo.controller;

import javax.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;
import net.demo.dto.LoginRequest;
import net.demo.entity.ResponseApi;
import net.demo.model.AppUser;
import net.demo.dto.UserResponseDTO;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import net.demo.dto.UserNewDTO;
import net.demo.service.UserService;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final ModelMapper modelMapper;

    @PostMapping("/signin")
    @ApiOperation(value = "${UserController.signin}")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 401, message = "Invalid username/password supplied")})
    public String login(
            @ApiParam("Username") @RequestParam String username,
            @ApiParam("Password") @RequestParam String password) {
        String signin;
        signin = userService.signin(username, password);
        return signin;
    }

    @PostMapping("/signinRest")
    @ApiOperation(value = "${UserController.signin}")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 401, message = "Invalid username/password supplied")})
    public ResponseEntity<ResponseApi> signinRest(
            @ApiParam("LoginRequest loginRequest")
            @RequestBody LoginRequest loginRequest) {
        ResponseApi response = new ResponseApi();
        String signin = userService.signin(loginRequest.getUsername(), loginRequest.getPassword());
        response.setStatus(true);
        response.setData(signin);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/signup")
    @ApiOperation(value = "${UserController.signup}")
    @ApiResponses(value = {//
            @ApiResponse(code = 400, message = "Something went wrong"), //
            @ApiResponse(code = 403, message = "Access denied"), //
            @ApiResponse(code = 401, message = "Username is already in use")})
    public String signup(@ApiParam("Signup User") @RequestBody UserNewDTO user) {
        AppUser appUser = modelMapper.map(user, AppUser.class);
        String signup = userService.signup(appUser);
        return signup;
    }

    @PostMapping("/signupRest")
    @ApiOperation(value = "${UserController.signup}")
    @ApiResponses(value = {//
            @ApiResponse(code = 400, message = "Something went wrong"), //
            @ApiResponse(code = 403, message = "Access denied"), //
            @ApiResponse(code = 401, message = "Username is already in use")})
    public ResponseApi signupRest(@ApiParam("Signup User") @RequestBody UserNewDTO user) {
        AppUser appUser = modelMapper.map(user, AppUser.class);
        String signup = userService.signup(appUser);
        ResponseApi responseApi = new ResponseApi(true, null,signup);
        return responseApi;
    }

    @DeleteMapping(value = "/{username}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @ApiOperation(value = "${UserController.delete}", authorizations = {@Authorization(value = "apiKey")})
    @ApiResponses(value = {//
            @ApiResponse(code = 400, message = "Something went wrong"), //
            @ApiResponse(code = 403, message = "Access denied"), //
            @ApiResponse(code = 404, message = "The user doesn't exist"), //
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public String delete(@ApiParam("Username") @PathVariable String username) {
        userService.delete(username);
        return username;
    }

    @GetMapping(value = "/{username}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @ApiOperation(value = "${UserController.search}", response = UserResponseDTO.class, authorizations = {@Authorization(value = "apiKey")})
    @ApiResponses(value = {//
            @ApiResponse(code = 400, message = "Something went wrong"), //
            @ApiResponse(code = 403, message = "Access denied"), //
            @ApiResponse(code = 404, message = "The user doesn't exist"), //
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public ResponseApi search(@ApiParam("Username") @PathVariable String username) {
        AppUser appUser = userService.search(username);
        UserResponseDTO userResponseDTO = modelMapper.map(appUser, UserResponseDTO.class);
        return new ResponseApi(userResponseDTO);
    }

    @GetMapping(value = "/me")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
    @ApiOperation(value = "${UserController.me}", response = UserResponseDTO.class, authorizations = {@Authorization(value = "apiKey")})
    @ApiResponses(value = {//
            @ApiResponse(code = 400, message = "Something went wrong"), //
            @ApiResponse(code = 403, message = "Access denied"), //
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public ResponseApi whoami(HttpServletRequest req) {
        AppUser appUser = userService.whoami(req);
        UserResponseDTO userResponseDTO = modelMapper.map(appUser, UserResponseDTO.class);
        return new ResponseApi(userResponseDTO);
    }

    @GetMapping("/refresh")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
    public String refresh(HttpServletRequest req) {
        return userService.refresh(req.getRemoteUser());
    }

}
