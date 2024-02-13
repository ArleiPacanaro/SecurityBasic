## Spring Security (Lista de ativos da bolsa)

Fluxo para criação do banco de dados:

`docker run --name spring-arlei -e POSTGRES_PASSWORD=102030 -d -p 5432:5432 postgres`

Carga inicial esta dentro da pasta `sql_carga/insertAtivos`

Agora para rodar o projeto execute: `mvn clean install` para instalar as dependências e `mvn spring-boot:run` para subir a aplicação.

Precisa ter o Java17, Maven e Docker Client ou Postgre instalados.

1) Adiciona no POM XML o spring security neste momento a aplicação já tera uma tela pedindo usuário e senha
   por default podemos usar : user e a senha que foi gerada randomicamente pelo spring boot, capturando no log da subida aplicação.
   POM:
   
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
   
2) Incluindo no properties um usuário e senha para o spring security para acessar o recurso que necessita de aunteticação será aberta uma tela solicitando, podendo usar ate o spring cloud.

#spring.security.user.name=arlei
#spring.security.user.password=102030
   
3) criei a pasta security com um bean padrão para informar quais endpoints necessitam ou não de autenticação, esta uma receta de bolo
Por ser uma configuration e também conter a anotações de EnableWebSecurity o Spring já assumir estas configurações do objeto que representa a classe SecurityFilterChain, aqui a mágica da framework começa a acontecer.

SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(
                        authorizeConfig -> {
                             authorizeConfig.requestMatchers("/ativos/buscarTodos").permitAll();
                             authorizeConfig.requestMatchers("/logout").permitAll();
                             // Acima permitindo que os endpoints marcados sejam acessados sem autenticação...
                             authorizeConfig.anyRequest().authenticated();
                             // aqui configurando que os demais endpoints so devem ser acessados com autemticação
                         }).oauth2Login(Customizer.withDefaults())
                // usando uma autenticação básica. agora mudei para oauth2
                 .build();
     }
   
Principais Classes e Interfaces do Spring utilizadas: SecurityFilterChain e HttpSecurity

Texto interessante sobre o Spring Secutiry:

A segurança de aplicativos é uma preocupação primordial no desenvolvimento
de software atual.
Com a crescente complexidade das aplicações web e a constante evolução das
ameaças cibernéticas, garantir a segurança dos dados e de usuários tornou-se uma
tarefa crítica. É aqui que o Spring Security entra em ação, oferecendo uma solução
poderosa para proteger suas aplicações Java de forma eficaz.
Caso esse seja seu primeiro contato com o Spring Security, ele é um módulo
do Spring Framework que visa tornar a implementação de recursos de segurança em
aplicativos Java mais simples e robusta.
Ele fornece uma estrutura abrangente para autenticação (verificando a
identidade de usuários) e autorização (determinando quais ações eles têm permissão
para realizar). Além disso o Spring Security lida com questões como prevenção contra
ataques de segurança.

Temos que CSRF é a abreviação de Cross-Site Request Forgery ou
Falsificação de Solicitações entre Sites. Este é um tipo de ataque cibernético que
explora a confiança que um aplicativo web tem em seu usuário autenticado. No CSRF,
um atacante induz o usuário a realizar uma ação não intencional em um aplicativo em
que ele está autenticado. Essa ação pode variar de alterar a senha do usuário a
realizar uma compra não autorizada em um site de comércio eletrônico.

O XSS, ou Cross-Site Scripting, é uma vulnerabilidade de segurança comum
em aplicações web que permite que atacantes injetem código malicioso (geralmente
JavaScript) em páginas web visualizadas por outros usuários. Essa ameaça pode ter
consequências graves, indo desde o roubo de informações confidenciais até o
sequestro de contas de usuário.
PDF

O SQL Injection, ou Injeção de SQL, é uma técnica utilizada por atacantes
para manipular consultas SQL de uma aplicação, injetando código SQL malicioso.
Isso ocorre quando as entradas de usuário ou outras fontes de dados não
confiáveis não são devidamente sanitizadas ou validadas antes de serem
incorporadas às instruções SQL.
Ao injetar código SQL prejudicial, os atacantes podem executar ações não
autorizadas no banco de dados, potencialmente acessando dados sensíveis,
modificando ou excluindo registros ou até mesmo assumindo o controle do servidor
de banco de dados inteiro.
Principais Recursos do Spring Security
O Spring Security oferece uma variedade de recursos essenciais para proteger
suas aplicações Java. A seguir, você tem uma lista com alguns deles.
Autenticação Flexível
O Spring Security suporta uma ampla gama de métodos de autenticação, como
autenticação baseada em formulário, autenticação com tokens JWT (JSON Web
Tokens) e autenticação baseada em SSO (Single Sign-On). Isso permite que você
escolha a abordagem mais adequada às necessidades específicas do seu aplicativo.

Autorização Granular
Com o Spring Security, você pode definir regras de autorização detalhadas
para determinar quem tem acesso a quais recursos em seu aplicativo. Isso pode ser
alcançado usando anotações ou configurações XML, tornando o processo de
autorização altamente personalizável.

Proteção contra Vulnerabilidades
O Spring Security inclui medidas integradas para proteger seu aplicativo contra
ameaças comuns, como CSRF, XSS e SQL Injection (que conhecemos nos passos
anteriores).
Essas medidas ajudam a garantir que os atacantes não possam explorar essas
vulnerabilidades para comprometer a segurança de sua aplicação.

Integração com Frameworks de Autenticação Externos
O Spring Security pode ser facilmente integrado com sistemas de autenticação
externos, como LDAP, OAuth, OpenID Connect e muito mais.
Isso simplifica a implementação de autenticação única (SSO) e permite que
usuários utilizem suas contas de terceiros para acessar seu aplicativo.

Auditoria e Logs de Segurança
O Spring Security oferece recursos integrados para auditoria e geração de logs
de segurança. Isso permite que você monitore e registre todas as atividades
relacionadas à segurança em seu aplicativo, facilitando a detecção de possíveis
ameaças ou violações.

referencias:
SPRING.IO. Getting Spring Security. 2023. Disponível em:
<https://docs.spring.io/spring-security/reference/getting-spring-security.html>. Acesso
em: 26 out. 2023.
SPRING.IO. Securing a Web Application. 2023. Disponí






