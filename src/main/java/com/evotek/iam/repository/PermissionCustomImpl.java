package com.evotek.iam.repository;

import com.evotek.iam.model.Permission;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PermissionCustomImpl implements PermissionCustom {
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<Permission> search(String keyword, int pageIndex, int pageSize, String sortBy) {
        Map<String, Object> values = new HashMap<>();
        String sql = "select p from Permission p " + createWhereQuery(keyword, values);
        Query query = entityManager.createQuery(sql, Permission.class);
        values.forEach(query::setParameter);
        query.setFirstResult((pageIndex - 1) * pageSize);
        query.setMaxResults(pageSize);
        return query.getResultList();
    }

    private String createWhereQuery(String keyword, Map<String, Object> values) {
        StringBuilder sql = new StringBuilder();
        if (!keyword.isBlank()) {
            sql.append(
                    " where ( lower(p.resourceId) like :keyword"
                            + " or lower(p.scope) like :keyword )");
            values.put("keyword", encodeKeyword(keyword));
        }
        return sql.toString();
    }

    public String encodeKeyword(String keyword) {
        if (keyword == null) {
            return "%";
        }

        return "%" + keyword.trim().toLowerCase() + "%";
    }
}