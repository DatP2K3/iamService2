package com.evotek.iam.repository;

import com.evotek.iam.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserRepositoryCustomImpl implements UserRepositoryCustom {
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<User> search(String keyword, int pageIndex, int pageSize, String sortBy) {
        Map<String, Object> values = new HashMap<>();
        String sql = "select e from User e " + createWhereQuery(keyword, values) + createOrderQuery(sortBy);
        Query query = entityManager.createQuery(sql, User.class);
        values.forEach(query::setParameter);
        query.setFirstResult((pageIndex - 1) * pageSize);
        query.setMaxResults(pageSize);
        return query.getResultList();
    }

    private String createWhereQuery(String keyword, Map<String, Object> values) {
        StringBuilder sql = new StringBuilder();
        sql.append(" where e.deleted = false");
        if (!keyword.isBlank()) {
            sql.append(
                    " and ( lower(e.username) like :keyword"
                            + " or lower(e.email) like :keyword )");
            values.put("keyword", encodeKeyword(keyword));
        }
        return sql.toString();
    }

    public StringBuilder createOrderQuery(String sortBy) {
        StringBuilder hql = new StringBuilder(" ");
        if (StringUtils.hasLength(sortBy)) {
            hql.append(" order by e.").append(sortBy.replace(".", " "));
        }
        return hql;
    }

    public String encodeKeyword(String keyword) {
        if (keyword == null) {
            return "%";
        }

        return "%" + keyword.trim().toLowerCase() + "%";
    }
}
