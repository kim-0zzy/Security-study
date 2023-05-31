package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

// UserDetail을 구현한 구현체 = User클래스
public class AccountContext extends User {

    private final Account account;
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount(){
        return account;
    }
}
