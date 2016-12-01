package org.jboss.eap.example.security.loginmodule;

import java.security.Principal;
import java.security.acl.Group;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import javax.transaction.SystemException;
import javax.transaction.Transaction;
import javax.transaction.TransactionManager;

import org.jboss.security.PicketBoxMessages;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.jboss.security.plugins.TransactionManagerLocator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JDBC based login module that supports authentication and role mapping. It
 * is based on two logical tables:
 * <ul>
 * <li>Principals(PrincipalID text, Password text)
 * <li>Roles(PrincipalID text, Role text, RoleGroup text)
 * </ul>
 * <p>
 * LoginModule options:
 * <ul>
 * <li><em>dsJndiName</em>: The name of the DataSource of the database
 * containing the Principals, Roles tables
 * <li><em>principalsQuery</em>: The prepared statement query, equivalent to:
 * 
 * <pre>
 * "select Password from Principals where PrincipalID=?"
 * </pre>
 * 
 * <li><em>rolesQuery</em>: The prepared statement query, equivalent to:
 * 
 * <pre>
 * "select Role, RoleGroup from Roles where PrincipalID=?"
 * </pre>
 * </ul>
 *
 * @author <a href="mailto:on@ibis.odessa.ua">Oleg Nitz</a>
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class DBRolesLoginModule extends AbstractServerLoginModule {
    /**
     * Logger for this class
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(DBRolesLoginModule.class);

    // see AbstractServerLoginModule
    private static final String DS_JNDI_NAME = "dsJndiName";
    private static final String ROLES_QUERY = "rolesQuery";
    private static final String SUSPEND_RESUME = "suspendResume";
    private static final String PRINCIPALS_QUERY = "principalsQuery";
    private static final String TRANSACTION_MANAGER_JNDI_NAME = "transactionManagerJndiName";

    private static final String[] ALL_VALID_OPTIONS = { DS_JNDI_NAME,
            ROLES_QUERY, SUSPEND_RESUME, PRINCIPALS_QUERY,
            TRANSACTION_MANAGER_JNDI_NAME };

    /** The JNDI name of the DataSource to use */
    protected String dsJndiName;
    /** The sql query to obtain the user roles */
    protected String rolesQuery;
    /** Whether to suspend resume transactions during database operations */
    protected boolean suspendResume = true;
    /** The JNDI name of the transaction manager */
    protected String txManagerJndiName = "java:/TransactionManager";
    /** The TransactionManagaer instance to be used */
    protected TransactionManager tm = null;

    protected Principal identity;

    /**
     * Initialize this LoginModule.
     * 
     * @param options
     *            - dsJndiName: The name of the DataSource of the database
     *            containing the Principals, Roles tables principalsQuery: The
     *            prepared statement query, equivalent to: "select Password from
     *            Principals where PrincipalID=?" rolesQuery: The prepared
     *            statement query, equivalent to: "select Role, RoleGroup from
     *            Roles where PrincipalID=?"
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler,
            Map<String, ?> sharedState, Map<String, ?> options) {

        addValidOptions(ALL_VALID_OPTIONS);
        super.initialize(subject, callbackHandler, sharedState, options);
        dsJndiName = (String) options.get(DS_JNDI_NAME);
        if (dsJndiName == null)
            dsJndiName = "java:/DefaultDS";
        Object tmp = options.get(ROLES_QUERY);
        if (tmp != null)
            rolesQuery = tmp.toString();
        tmp = options.get(SUSPEND_RESUME);
        if (tmp != null)
            suspendResume = Boolean.valueOf(tmp.toString()).booleanValue();
        // Get the Transaction Manager JNDI Name
        String jname = (String) options.get(TRANSACTION_MANAGER_JNDI_NAME);
        if (jname != null)
            this.txManagerJndiName = jname;

        LOGGER.trace(
                "Module options [dsJndiName: {}, rolesQuery: {}, suspendResume: {}],",
                dsJndiName, rolesQuery, suspendResume);

        LOGGER.trace("Shared State: \n {}", sharedState);

        try {
            if (this.suspendResume)
                tm = this.getTransactionManager();
        } catch (NamingException e) {
            throw PicketBoxMessages.MESSAGES.failedToGetTransactionManager(e);
        }

    }

    /**
     * Execute the rolesQuery against the dsJndiName to obtain the roles for the
     * authenticated user.
     * 
     * @return Group[] containing the sets of roles
     */
    protected Group[] getRoleSets() throws LoginException {
        if (rolesQuery != null) {
            String username = getUsername();
            LOGGER.trace("Executing query {} with username {}",rolesQuery, username);
            Group[] roleSets = getRoleSets(username);
            return roleSets;
        }
        return new Group[0];
    }

    /**
     * Obtains the username from the identity
     * @return
     */
    private String getUsername() {
        return getIdentity().getName();
    }

    /**
     * A hook to allow subclasses to convert a password from the database into a
     * plain text string or whatever form is used for matching against the user
     * input. It is called from within the getUsersPassword() method.
     * 
     * @param rawPassword
     *            - the password as obtained from the database
     * @return the argument rawPassword
     */
    protected String convertRawPassword(String rawPassword) {
        return rawPassword;
    }

    protected TransactionManager getTransactionManager()
            throws NamingException {
        TransactionManagerLocator tml = new TransactionManagerLocator();
        return tml.getTM(this.txManagerJndiName);
    }

    /**
     * Execute the rolesQuery against the dsJndiName to obtain the roles for the
     * authenticated user.
     * 
     * @return Group[] containing the sets of roles
     */
    Group[] getRoleSets(String username) throws LoginException {

        LOGGER.debug("Fetching Role Set for {}", username);

        Connection conn = null;
        HashMap<String, Group> setsMap = new HashMap<String, Group>();
        PreparedStatement ps = null;
        ResultSet rs = null;

        TransactionManager tm = null;

        if (suspendResume) {
            TransactionManagerLocator tml = new TransactionManagerLocator();
            try {
                tm = tml.getTM(txManagerJndiName);
            } catch (NamingException e1) {
                throw new RuntimeException(e1);
            }
            if (tm == null)
                throw PicketBoxMessages.MESSAGES
                        .invalidNullTransactionManager();
        }
        Transaction tx = null;
        if (suspendResume) {
            // tx = TransactionDemarcationSupport.suspendAnyTransaction();
            try {
                tx = tm.suspend();
            } catch (SystemException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(dsJndiName);
            conn = ds.getConnection();
            // Get the user role names
            LOGGER.trace("Executing query %s with username %s",rolesQuery, username);
            ps = conn.prepareStatement(rolesQuery);
            try {
                ps.setString(1, username);
            } catch (ArrayIndexOutOfBoundsException ignore) {
                // The query may not have any parameters so just try it
            }
            rs = ps.executeQuery();
            if (rs.next() == false) {
                throw PicketBoxMessages.MESSAGES
                        .noMatchingUsernameFoundInRoles();
            }

            do {
                String name = rs.getString(1);
                String groupName = rs.getString(2);
                if (groupName == null || groupName.length() == 0)
                    groupName = "Roles";
                Group group = (Group) setsMap.get(groupName);
                if (group == null) {
                    group = new SimpleGroup(groupName);
                    setsMap.put(groupName, group);
                }

                try {
                    Principal p = createIdentity(name);
                    group.addMember(p);
                } catch (Exception e) {
                    LOGGER.error("Failed to create principal {}",name,
                            e);
                }
            } while (rs.next());

            LOGGER.debug("Role Set obtained={}", setsMap);
        } catch (NamingException ex) {
            LoginException le = new LoginException(PicketBoxMessages.MESSAGES
                    .failedToLookupDataSourceMessage(dsJndiName));
            le.initCause(ex);
            throw le;
        } catch (SQLException ex) {
            LoginException le = new LoginException(
                    PicketBoxMessages.MESSAGES.failedToProcessQueryMessage());
            le.initCause(ex);
            throw le;
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                }
            }
            if (ps != null) {
                try {
                    ps.close();
                } catch (SQLException e) {
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (Exception ex) {
                }
            }
            if (suspendResume) {
                // TransactionDemarcationSupport.resumeAnyTransaction(tx);
                try {
                    tm.resume(tx);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }

        Group[] roleSets = new Group[setsMap.size()];
        setsMap.values().toArray(roleSets);
        return roleSets;
    }

    @Override
    protected Principal getIdentity() {

        if (identity == null) {
            identity = subject.getPrincipals(KerberosPrincipal.class).iterator()
                    .next();
            LOGGER.debug(
                    "Identity obtained from previous LoginModule : classname={} name={}",
                    identity.getClass(), identity.getName());
        }

        return identity;
    }
}
