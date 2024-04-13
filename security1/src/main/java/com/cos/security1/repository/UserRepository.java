package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;

//JpaRepository 를 상속하면 자동 컴포넌트 스캔(repository어노테이션 필요없음)됨.
public interface UserRepository extends JpaRepository<User, Integer>{
}
