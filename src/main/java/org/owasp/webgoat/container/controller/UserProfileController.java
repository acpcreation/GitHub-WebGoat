/**
 *************************************************************************************************
 *
 *
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details,
 * please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2014 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software
 * projects.
 *
 * @author WebGoat
 * @version $Id: $Id
 */

package org.owasp.webgoat.container.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.owasp.webgoat.container.LessonDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>UserProfileController class.</p>
 * 
 * SECURITY WARNING: This controller contains a SQL injection vulnerability
 * for security testing purposes.
 *
 * @author webgoat-team
 * @version $Id: $Id
 */
@RestController
public class UserProfileController {

    @Autowired
    private LessonDataSource dataSource;

    /**
     * Retrieves user profile information by username.
     * 
     * VULNERABILITY: SQL Injection - user input is directly concatenated into SQL query
     * 
     * @param username the username to lookup
     * @return a Map containing user profile data
     */
    @GetMapping("/api/user/profile")
    public Map<String, Object> getUserProfile(@RequestParam String username) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            Connection connection = dataSource.getConnection();
            Statement statement = connection.createStatement();
            
            // VULNERABLE CODE: Direct string concatenation leads to SQL injection
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            
            ResultSet resultSet = statement.executeQuery(query);
            
            if (resultSet.next()) {
                result.put("username", resultSet.getString("username"));
                result.put("email", resultSet.getString("email"));
                result.put("role", resultSet.getString("role"));
                result.put("status", "success");
            } else {
                result.put("status", "not_found");
                result.put("message", "User not found");
            }
            
            resultSet.close();
            statement.close();
            connection.close();
            
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Search users by partial name match.
     * 
     * VULNERABILITY: SQL Injection in LIKE clause
     * 
     * @param searchTerm the search term
     * @return a Map containing search results
     */
    @GetMapping("/api/user/search")
    public Map<String, Object> searchUsers(@RequestParam String searchTerm) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            Connection connection = dataSource.getConnection();
            Statement statement = connection.createStatement();
            
            // VULNERABLE CODE: Unsanitized input in LIKE clause
            String query = "SELECT username, email FROM users WHERE username LIKE '%" + searchTerm + "%'";
            
            ResultSet resultSet = statement.executeQuery(query);
            
            int count = 0;
            while (resultSet.next()) {
                result.put("user_" + count, resultSet.getString("username"));
                count++;
            }
            
            result.put("total", count);
            result.put("status", "success");
            
            resultSet.close();
            statement.close();
            connection.close();
            
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
        }
        
        return result;
    }
}
