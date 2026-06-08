/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SqlInjectionChallengeSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private LessonDataSource lessonDataSource;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void testSqlInjectionAttemptOnRegisterUser() throws Exception {
        Connection mockConnection = org.mockito.Mockito.mock(Connection.class);
        PreparedStatement mockPreparedStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        ResultSet mockResultSet = org.mockito.Mockito.mock(ResultSet.class);

        when(lessonDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false); // No user found with the literal malicious username

        String maliciousUsername = "testuser' OR 1=1 --";
        String password = "password";
        String email = "test@example.com";

        mockMvc.perform(put("/WebGoat/SqlInjectionAdvanced/register")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username_reg", maliciousUsername)
                .param("password_reg", password)
                .param("email_reg", email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.feedback").value("user.created")); // Expect user to be created with the literal username
    }

    @Test
    void testValidUserRegistration() throws Exception {
        Connection mockConnection = org.mockito.Mockito.mock(Connection.class);
        PreparedStatement mockPreparedStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        ResultSet mockResultSet = org.mockito.Mockito.mock(ResultSet.class);

        when(lessonDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false); // No user found

        String username = "validuser";
        String password = "password";
        String email = "valid@example.com";

        mockMvc.perform(put("/WebGoat/SqlInjectionAdvanced/register")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username_reg", username)
                .param("password_reg", password)
                .param("email_reg", email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.feedback").value("user.created"));
    }

    @Test
    void testExistingUserRegistration() throws Exception {
        Connection mockConnection = org.mockito.Mockito.mock(Connection.class);
        PreparedStatement mockPreparedStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        ResultSet mockResultSet = org.mockito.Mockito.mock(ResultSet.class);

        when(lessonDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true); // User found

        String username = "existinguser";
        String password = "password";
        String email = "existing@example.com";

        mockMvc.perform(put("/WebGoat/SqlInjectionAdvanced/register")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username_reg", username)
                .param("password_reg", password)
                .param("email_reg", email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.feedback").value("user.exists"));
    }
}