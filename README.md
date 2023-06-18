### Spring Security

用户信息认证和授权

#### 1 Spring Security是什么？

Spring Security是一个能够为基于Spring的企业应用系统提供声明式的安全访问控制解决方案的安全框架。它提供了一组可以在Spring应用上下文中配置的Bean，充分利用了Spring IoC，DI控制反转和AOP功能，为应用系统提供声明式的安全访问控制功能，减少了为企业系统安全控制编写大量重复代码的工作

#### 2 Spring Security原理

##### 2.1基本原理

![img](https://pic4.zhimg.com/80/v2-4ed025e43a1c8d4b5ac3d08a6e3517db_1440w.webp)

- **认证流程：**
  ![img](https://pic4.zhimg.com/80/v2-6fe78141aa34ec73a092103e5a76a063_1440w.webp)

- **鉴权流程：**
  ![img](https://pic1.zhimg.com/80/v2-1c5451c4fd114beed23c253898f73030_1440w.webp)

如上图，Spring Security包含了众多的过滤器，这些过滤器形成了一条链，所有请求都必须通过这些过滤器才能成功访问到资源。其中

`UsernamePasswordAuthenticationFilter`：处理基于表单方式的登录认证。将请求信息封装为`Authentication`，实现类为 `UsernamePasswordAuthenticationToken`，并将其交由`AuthenticationManager` 认证(详见该过滤器中 `attemptAuthentication()` 方法) 

`BasicAuthenticationFilter`：处理基于HTTP Basic方式的登录验证。同理也会将请求信息封装为`UsernamePasswordAuthenticationToken`，并将其交由`AuthenticationManager` 认证

`AuthenticationManager`：调用该类的`authenticate()`方法进行认证，该方法会通过子类 `ProviderManager`，经过辗转找到对应类型的`AuthenticationProvider `，`AuthenticationProvider `获取用户信息并核对认证，最后重新封装 `Authentication` 返回给最开始的认证处理过滤器(例如：`UsernamePasswordAuthenticationFilter`)。`AuthenticationManager`是用于定义 Spring Security 的过滤器如何执行 身份验证的API. 然后,由调用 `AuthenticationManager` 的控制器(即 Spring Security 的Spring Security 的过滤器) 在 SecurityContextHolder上设置返回的身份验证. 如果您不与 Spring Security 的过滤器集成,则可以直接设置 `SecurityContextHolder`,并且不需要使用 `AuthenticationManager`

`AuthenticationProvider `：每个 `AuthenticationProvider ` 都会实现 `support()` 方法，表明自己支持的认证类型

`FilterSecurityInterceptor`：过滤链尾部的拦截器，判断当前请求身份认证是否成功 ，用户认证成功则获取 `ConfigAttribute` ，继续调用访问控制器 `AccessDecisionManager` 对当前请求进行鉴权，当身份认证失败或权限不足时会抛出相应异常

`ExceptionTranslateFilter`：捕获`FilterSecurityInterceptor`抛出的异常并进行处理。但他只会处理两类异常：`AuthenticationException` 和 `AccessDeniedException` ，其他异常会继续抛出。比如需要身份认证时将请求重定向到相应的认证页面，当认证失败或者权限不足时返回相应的提示信息

##### 2.2SecurityContextHolder

> SecurityContextHolder是Spring Security最基本的组件了，是用来存放SecurityContext的对象。表示用户已通过身份验证的最简单方法是直接设置SecurityContextHolder，则不会走后续过滤器
>
> 如，Authentication authentication = authenticationManager
>         .authenticate(new UsernamePasswordAuthenticationToken("lsh", "123456"));
>
> ​		SecurityContextHolder.getContext().setAuthentication(authentication);

### ![securitycontextholder](https://resources.jcohy.com/jcohy-docs/images/2.4.5/spring-security/servlet/authentication/architecture/securitycontextholder.png)

**模式：** 

- 默认模式：使用ThreadLocal来存储认证信息。这是一种与线程绑定的策略。Spring Security在用户登录时自动绑定认证信息到当前线程，在用户退出时，自动清除当前线程的认证信息，将内容存储在cookie-session中

- MODE_GLOBAL：表示SecurityContextHolder对象是全局的，应用中所有线程都可以访问。MODE_GLOBAL将 SecurityContext存储在全局静态变量中，使得它可以在应用程序的任何部分和任何线程中进行访问

- MODE_INHERITABLETHREADLOCAL：用于线程有父子关系的情境中，线程希望自己的子线程和自己有相同的安全性

#### 3 开启Spring Security 

- **基于的HTTP认证：**

当Spring项目引入Spring Security依赖的时候，项目会默认开启如下配置：

```java
security:
  basic:
    enabled: true
```

这个配置开启了一个HTTP basic类型的认证，所有服务的访问都必须先过这个认证

- **基于表单认证：**

我们可以通过配置将HTTP basic认证修改为基于表单的认证方式

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单方式
          			.and()
           			.httpBasic() // HTTP Basic方式
                .and()
                .authorizeRequests() // 授权配置
                .anyRequest()  // 所有请求
                .authenticated(); // 都需要认证
    }
}
```

#### 4 Spring Security 自定义用户认证

**自定义认证过程：**

实现Spring Security提供的 `UserDetailsService` 接口，并将该组件放入容器中就能自动生效，该接口只有一个抽象方法`loadUserByUsername`，源码如下：

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

`loadUserByUsername`方法返回值为 `UserDetails` 对象，该对象也是一个接口，包含一些描述用户信息的方法，源码如下：

```java
public interface UserDetails extends Serializable {
	// 获取用户包含的权限集合，权限是一个继承了 `GrantedAuthority` 的对象
    Collection<? extends GrantedAuthority> getAuthorities();
	// 获取密码
    String getPassword();
	// 获取用户名
    String getUsername();
	// 判断账户是否未过期
    boolean isAccountNonExpired();
	// 判断账户是否未锁定
    boolean isAccountNonLocked();
	// 判断用户凭证是否没过期，即密码是否未过期
    boolean isCredentialsNonExpired();
	// 判断用户是否可用
    boolean isEnabled();
}
```

**也可以手动将权限信息添加到authentication：**

```java
/**
  * 设置权限信息到authentication中
  */
public Collection<? extends GrantedAuthority> getAuthorities() {
  	...
    // 根据自定义逻辑来返回用户权限，如果用户权限返回空或者和拦截路径对应权限不同，验证不通过
    if (!permissions.isEmpty()) {
         List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
         for (String temp : permissions) {
             GrantedAuthority au = new CustomizeAuthority(temp);
             list.add(au);
         }
         return list;
    }
    return null;
}
// 自定义权限模型
public final class CustomizeAuthority implements GrantedAuthority {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final String permission;

	public CustomizeAuthority(String permission) {
		Assert.hasText(permission, "A granted authority textual representation is required");
		this.permission = permission;
	}

	@Override
	public String getAuthority() {
		return permission;
	}
  ...
}
```

**自定义认证成功 or 认证失败逻辑：**

实现 `AuthenticationFailureHandler` 或 `AuthenticationSuccessHandler`，并在Spring Security配置类进行配置：

```java
/** 安全配置 */
@Override
protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            .formLogin() // 表单登录
            // http.httpBasic() // HTTP Basic
            .loginProcessingUrl("/login") // 处理表单登录 URL
            .successHandler(authenticationSuccessHandler) // 认证成功处理
            .failureHandler(authenticationFailureHandler) // 认证失败处理
            .and()
            .authorizeRequests() // 授权配置
            .anyRequest()  // 所有请求
            .authenticated() // 都需要认证
            .and().csrf().disable(); // csrf禁用
}
```

**Spring Security 短信验证码登录：**

Spring Security 默认只提供了账号密码的登录认证逻辑，手机短信验证码登录认证功能需要自行实现，可以模仿Spring Security账号密码登录逻辑代码来实现

#### 5 Spring Security 权限控制

Spring Security权限控制可以配合授权注解使用，具体注解参考[Spring-Security保护方法](https://mrbird.cc/Spring-Security保护方法.html)，要开启这些注解，需要在 Spring Security 配置文件中添加如下配置：

```java
// prePostEnabled = true。会解锁@PreAuthorize和@PostAuthorize两个注解
// 使用表达式时间方法级别的安全性4个注解可用
// @PreAuthorize 在方法调用之前, 基于表达式的计算结果来限制对方法的访问
// @PostAuthorize 允许方法调用, 但是如果表达式计算结果为false, 将抛出一个安全性异常
// @PostFilter 允许方法调用, 但必须按照表达式来过滤方法的结果
// @PreFilter 允许方法调用, 但必须在进入方法之前过滤输入值
@EnableWebSecurity  //注解开启Spring Security功能
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
}
```

**基本使用：**

- ```java
  /**
       * 登录验证
       * 
       * @param username 用户名
       * @param password 密码
       * @param code 验证码
       * @param uuid 唯一标识
       * @return 结果
       */
      public String login(String username, String password, String code, String uuid)
      {
         	...
          // 用户验证
          Authentication authentication = null;
          try
          {
              // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername。该过程查询数据库中的LoginUser
            	// 该方法会把数据库中查询出的loginUser封装到Authentication，最后再存在security上下文中
            	// 使用了security认证流程或手动将权限信息添加到authentication中，在鉴权的时候直接使用security鉴权。如，直接使用@PreAuthorize("hasAuthority('core:abnormalEvent:query')")
              authentication = authenticationManager
                      .authenticate(new UsernamePasswordAuthenticationToken(username, password));
          }
          catch (Exception e)
          {
              ...
          }
          AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
          // 因为使用了security认证流程，因而需要实现UserDetails
          LoginUser loginUser = (LoginUser) authentication.getPrincipal(); 
          recordLoginInfo(loginUser.getUserId());
          // 生成token
          return tokenService.createToken(loginUser);
      }
  
  
  /**
   * 用户验证处理
   * @author lsh
   */
  @Service
  public class UserDetailsServiceImpl implements UserDetailsService {
      private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
  
      @Resource
      private ISysUserService userService;
  
      @Resource
      private SysPermissionService permissionService;
  
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          SysUser user = userService.selectUserByUserName(username);
  				...
          return createLoginUser(user);
      }
  
      public UserDetails createLoginUser(SysUser user) {
          return new LoginUser(user, permissionService.getMenuPermission(user));
      }
  }
  
  
  /**
   * spring security配置
   * @author lsh
   */
  @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
  public class SecurityConfig extends WebSecurityConfigurerAdapter
  {
      ...
      
      /**
       * 解决 无法直接注入 AuthenticationManager
       *
       * @return
       * @throws Exception
       */
      @Bean
      @Override
      public AuthenticationManager authenticationManagerBean() throws Exception
      {
          return super.authenticationManagerBean();
      }
  
      /**
       * anyRequest          |   匹配所有请求路径
       * access              |   SpringEl表达式结果为true时可以访问
       * anonymous           |   匿名可以访问
       * denyAll             |   用户不能访问
       * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
       * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
       * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
       * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
       * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
       * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
       * permitAll           |   用户可以任意访问
       * rememberMe          |   允许通过remember-me登录的用户访问
       * authenticated       |   用户登录后可访问
       *
       */
      @Override
      protected void configure(HttpSecurity httpSecurity) throws Exception
      {
          httpSecurity
                  // CSRF禁用，因为不使用session
                  .csrf().disable()
                  // 认证失败处理类
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                  // 基于token，所以不需要session
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                  // 过滤请求
                  .authorizeRequests()
                  // 对于登录login 注册register 验证码captchaImage 允许匿名访问
                  .antMatchers("/login", "/register", "/captchaImage").anonymous()
                  .antMatchers(
                          HttpMethod.GET,
                          "/",
                          "/*.html",
                          "/**/*.html",
                          "/**/*.css",
                          "/**/*.js",
                          "/profile/**"
                  ).permitAll()
                  .antMatchers("/swagger-ui.html").anonymous()
                  .antMatchers("/swagger-resources/**").anonymous()
                  .antMatchers("/webjars/**").anonymous()
                  .antMatchers("/*/api-docs").anonymous()
                  .antMatchers("/druid/**").anonymous()
                  // 除上面外的所有请求全部需要鉴权认证
                  .anyRequest().authenticated()
                  .and()
                  .headers().frameOptions().disable();
          httpSecurity.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
          // 添加JWT filter
          httpSecurity.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
          // 添加CORS filter
          httpSecurity.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
          httpSecurity.addFilterBefore(corsFilter, LogoutFilter.class);
      }
  
      /**
       * 强散列哈希加密实现
       */
      @Bean
      public BCryptPasswordEncoder bCryptPasswordEncoder()
      {
          return new BCryptPasswordEncoder();
      }
  
      /**
       * 身份认证接口
       */
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception
      {
          auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
      }
  }
  
  /** 配置说明 */
  configure(WebSecurity web)：在这个方法里面放行的资源不走security过滤器直接放行
  configure(HttpSecurity http)：在这个方法里面放行的资源会走过滤器
  		1、.anonymous()：允许匿名用户访问资源(过滤器放行), 不允许已登入用户访问(过滤器拦截)
    	2、.permitAll()：允许匿名用户访问资源(过滤器放行), 登录/未登录的用户都可以访问资源
    	3、未配置的情况则会走过滤器进行认证
  ```


### OAuth2.0

第三方在用户授权后获取该用户在资源服务器上的资源

#### 1 授权码模式

![img](http://p.qpic.cn/pic_wework/4137543494/f4f213f888896868da889583d6d14021782e9b19d33174f6/0)

授权码模式是最能体现OAuth2协议，最严格，流程最完整的授权模式，流程如下所示：

A. 客户端将用户导向认证服务器

B. 用户决定是否给客户端授权

C. 同意授权后，认证服务器将用户导向客户端提供的URL，并附上授权码

D. 客户端通过重定向URL和授权码到认证服务器换取令牌(该过程是前端调用自己的认证服务器拿到自己的token，如：使用企微的token[`可根据corpId和应用secret获取`]和code[`可通过corpId获取`]来获取userId，再生成自己系统的token并返回)

E. 校验无误后发放令牌

其中A步骤，客户端申请认证的URI，包含以下参数：

- response_type：表示授权类型，必选项，此处的值固定为”code”，标识授权码模式

- client_id：表示客户端的ID，必选项

- redirect_uri：表示重定向URI，可选项

- scope：表示申请的权限范围，可选项

- state：表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值

下面是一个例子,

> ```java
> GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
>         &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
> ```

C步骤中，服务器回应客户端的URI，包含以下参数：

- code：表示授权码，必选项。该码的有效期应该很短，通常设为10分钟，客户端只能使用该码一次，否则会被授权服务器拒绝。该码与客户端ID和重定向URI，是一一对应关系
- state：如果客户端的请求中包含这个参数，认证服务器的回应也必须一模一样包含这个参数

下面是一个例子,

> ```java
> Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
> ```

D步骤中，客户端向认证服务器申请令牌的HTTP请求，包含以下参数：

- grant_type：表示使用的授权模式，必选项，此处的值固定为”authorization_code”

- code：表示上一步获得的授权码，必选项

- redirect_uri：表示重定向URI，必选项，且必须与A步骤中的该参数值保持一致

- client_id：表示客户端ID，必选项

下面是一个例子,

> ```java
> grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
> &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
> ```

E步骤中，认证服务器发送的HTTP回复，包含以下参数：

- access_token：表示访问令牌，必选项
- token_type：表示令牌类型，该值大小写不敏感，必选项，可以是bearer类型或mac类型
- expires_in：表示过期时间，单位为秒。如果省略该参数，必须其他方式设置过期时间
- refresh_token：表示更新令牌，用来获取下一次的访问令牌(可以跳过用户授权步骤直接获取token)，可选项
- scope：表示权限范围，如果与客户端申请的范围一致，此项可省略

下面是一个例子,

> ```java
>    	{
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
>        "example_parameter":"example_value"
>      }
>    ```

如下，企业微信OAuth2接入流程：

![img](http://p.qpic.cn/pic_wework/3033848529/181ef914a06abb1b1c775696a42f5cfcf7815f1675cdab77/0)

#### 2 简化模式

简化模式(implicit grant type)不通过第三方应用程序的服务器，直接在浏览器中向认证服务器申请令牌，跳过了"授权码"这个步骤，因此得名。所有步骤在浏览器中完成，令牌对访问者是可见的，且客户端不需要认证

![简化模式](https://box.kancloud.cn/2015-09-11_55f28833a90a6.png)

它的步骤如下：

> （A）客户端将用户导向认证服务器
>
> （B）用户决定是否给于客户端授权
>
> （C）假设用户给予授权，认证服务器将用户导向客户端指定的"重定向URI"，并在URI的Hash部分包含了访问令牌
>
> （D）浏览器向资源服务器发出请求，其中不包括上一步收到的Hash值
>
> （E）资源服务器返回一个网页，其中包含的代码可以获取Hash值中的令牌
>
> （F）浏览器执行上一步获得的脚本，提取出令牌
>
> （G）浏览器将令牌发给客户端

A步骤中，客户端发出的HTTP请求，包含以下参数：

- response_type：表示授权类型，此处的值固定为"token"，必选项
- client_id：表示客户端的ID，必选项
- redirect_uri：表示重定向的URI，可选项
- scope：表示权限范围，可选项
- state：表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值

下面是一个例子,

> ```java
>     GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
>         &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb 
>    ```

C步骤中，认证服务器回应客户端的URI，包含以下参数：

- access_token：表示访问令牌，必选项
- token_type：表示令牌类型，该值大小写不敏感，必选项
- expires_in：表示过期时间，单位为秒。如果省略该参数，必须其他方式设置过期时间
- scope：表示权限范围，如果与客户端申请的范围一致，此项可省略
- state：如果客户端的请求中包含这个参数，认证服务器的回应也必须一模一样包含这个参数

下面是一个例子,

> ```java
>    Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600
>    ```

在上面的例子中，认证服务器用HTTP头信息的Location栏，指定浏览器重定向的网址。注意，在这个网址的Hash部分包含了令牌

根据上面的D步骤，下一步浏览器会访问Location指定的网址，但是Hash部分不会发送。接下来的E步骤，服务提供商的资源服务器发送过来的代码，会提取出Hash中的令牌

#### 3 密码模式

密码模式(Resource Owner Password Credentials Grant)中，用户向客户端提供自己的用户名和密码。客户端使用这些信息，向"服务商提供商"索要授权。在这种模式中，用户必须把自己的密码给客户端，但是客户端不得储存密码。这通常用在用户对客户端高度信任的情况下，比如客户端是操作系统的一部分，或者由一个著名公司出品。而认证服务器只有在其他授权模式无法执行的情况下，才能考虑使用这种模式

![密码模式](https://box.kancloud.cn/2015-09-11_55f28853348d1.png)

它的步骤如下：

> （A）用户向客户端提供用户名和密码
>
> （B）客户端将用户名和密码发给认证服务器，向后者请求令牌
>
> （C）认证服务器确认无误后，向客户端提供访问令牌

B步骤中，客户端发出的HTTP请求，包含以下参数：

- grant_type：表示授权类型，此处的值固定为"password"，必选项
- username：表示用户名，必选项。
- password：表示用户的密码，必选项
- scope：表示权限范围，可选项

下面是一个例子,

> ```java
>    grant_type=password&username=johndoe&password=A3ddj3w
>    ```

C步骤中，认证服务器向客户端发送访问令牌，下面是一个例子,

> ```java
>      {
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
>        "example_parameter":"example_value"
>      }
>    ```

#### 4 客户端模式

客户端模式(Client Credentials Grant)指客户端以自己的名义，而不是以用户的名义，向"服务提供商"进行认证。严格地说，客户端模式并不属于OAuth框架所要解决的问题。在这种模式中，用户直接向客户端注册，客户端以自己的名义要求"服务提供商"提供服务，其实不存在授权问题

![客户端模式](https://box.kancloud.cn/2015-09-11_55f2886d27ab3.png)

它的步骤如下：

> （A）客户端向认证服务器进行身份认证，并要求一个访问令牌
>
> （B）认证服务器确认无误后，向客户端提供访问令牌

A步骤中，客户端发出的HTTP请求，包含以下参数：

- granttype：表示授权类型，此处的值固定为"clientcredentials"，必选项
- scope：表示权限范围，可选项
- client_id：客户端id
- secret：应用密钥

认证服务器必须以某种方式，验证客户端身份

B步骤中，认证服务器向客户端发送访问令牌，下面是一个例子,

> ```java
>     {
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "example_parameter":"example_value"
>      }
>    ```

### SpringSecurity Oauth2整合JWT

#### 1 引入依赖

```xml
<!-- jwt -->
<dependency>         
  <groupId>org.springframework.security</groupId>
 <artifactId>spring-security-jwt</artifactId>
 <version>1.0.10.RELEASE</version>
</dependency>

<!-- oauth2 -->
<dependency>            
  <groupId>org.springframework.security.oauth.boot</groupId>
 <artifactId>spring-security-oauth2-autoconfigure</artifactId>
 <version>2.1.3.RELEASE</version>
</dependency>

<!--jjwt依赖 解析token的-->
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt</artifactId>
  <version>0.9.1</version>
</dependency>
```

#### 2 授权服务器配置

```java
/**
 * 授权服务器配置
 * @author olic
 * @date 2023/6/811:26
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private JwtTokenEnhancer jwtTokenEnhancer;

    /**
     * 配置令牌端点的安全策略
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security// /oauth/token_key 公开
                 .tokenKeyAccess("permitAll()")
                // /oauth/check_token公开
                .checkTokenAccess("permitAll()")
                // 表单验证(申请令牌)
                .allowFormAuthenticationForClients();
    }

    /**
     * 客户端身份校验-内存形式
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
//        //内存配置形式
//        clients.inMemory()
//                //配置client Id
//                .withClient("admin_client_id")
//                //配置client-secret
//                .secret(passwordEncoder.encode("112233"))
//                //配置重定向的跳转，用于授权成功之后的跳转
//                .redirectUris("http://www.baidu.com")
//                //作用域
//                .scopes("all")
//                //不用跳转授权页面直接发code
//                .autoApprove(true)
//                //Grant_type 授权码模式。refresh_token: 可以使用refresh_token刷新access_token的过期时间，refreshToken可以提高安全性
//                .authorizedGrantTypes("authorization_code", "password", "refresh_token");
    }

    /**
     * 配置令牌服务
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //配置Jwt内容增强器
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer);
        delegates.add(jwtAccessTokenConverter);
        tokenEnhancerChain.setTokenEnhancers(delegates);
        endpoints.authenticationManager(authenticationManager)
   //授权码模式     	   		
          .authorizationCodeServices(authorizationCodeServices)
       //配置JWT令牌 
          .tokenEnhancer(jwtAccessTokenConverter)
                .tokenEnhancer(tokenEnhancerChain);
    }

}
```

#### 3 security配置

```java
/**
 * security相关配置
 * @author olic
 * @date 2023/6/811:54
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 加密器配置
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置jwtToken
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        //添加认证JwtToken的密钥
        jwtAccessTokenConverter.setSigningKey("test_key");
        return jwtAccessTokenConverter;
    }

//    /**
//     * 配置认证管理器 -- 内存形式
//     * @return
//     * @throws Exception
//     */
//    @Bean
//    public AuthorizationCodeServices authorizationCodeServices() throws Exception {
//        return new InMemoryAuthorizationCodeServices();
//    }

    /**
     * 配置认证管理器-数据源形式
     * @return
     * @throws Exception
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) throws Exception {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    /**
     * 重新实例化bean
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 客户端身份校验-数据源形式
     * @param dataSource
     * @return
     */
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource){
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        return clientDetailsService;
    }

    /**
     * security相关配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
         http.authorizeRequests()
                .antMatchers("/oauth/**", "/login/**", "/logout/**", "/user/**")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .csrf().disable();

    }

}
```

#### 4 其他配置

```java
/**
 * 配置jwt增强
 * @author olic
 * @date 2023/6/911:50
 */
@Configuration
public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        Map<String, Object> info = new HashMap<>();
        //我们需要增强的内容
        info.put("enhance", "enhance info");
        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);
        return oAuth2AccessToken;
    }
}
```

####  5 userServiceImpl

```java
/**
 * 获取用户信息
 * @author olic
 * @date 2023/6/812:57
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 加载用户信息
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.withUsername(username).password(passwordEncoder.encode("123456")).authorities("p1").build();
    }
}
```

#### 6 请求资源

```java
/**
 * @author olic
 * @date 2023/6/900:42
 */
@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * 获取用户信息
     * @param token
     * @return
     */
    @GetMapping("/getCurrentUserInfo")
    public Object getCurrentUserInfo(@RequestHeader("Authorization") String token) {
        System.out.println("解析token》》》");
        if (!StringUtils.isEmpty(token) && token.startsWith(AppConstants.TOKEN_PREFIX)) {
            token = token.replace(AppConstants.TOKEN_PREFIX, "");
        }
        return Jwts.parser()
             .setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }
}
```

#### 7 测试结果

##### 7.1获取code

```java
http://localhost:8081/oauth/authorize?response_type=code&client_id=admin_client_id&redirect_url=http://www.baidu.com&scope=all
```

![img](https://pic4.zhimg.com/80/v2-4bce8512d0720959106e48e5e8c8dcc3_1440w.webp)

##### 7.2获取token

![img](https://pic1.zhimg.com/80/v2-ceb94a7ee4af0d242c9502b10db1dfec_1440w.webp)

![img](https://pic2.zhimg.com/80/v2-301276b2cfe2697db46e5d7092ed34b9_1440w.webp)

##### 7.3测试令牌

![img](https://pic2.zhimg.com/80/v2-79a8d60cb93344c5a49ec308e8513e35_1440w.webp)

##### 7.4请求资源

![img](https://pic1.zhimg.com/80/v2-71dbc9ede596bc420ef2e54b70b37a50_1440w.webp)