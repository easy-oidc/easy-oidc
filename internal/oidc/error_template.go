// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

const errorPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        .error-card {
            background: white;
            border-radius: 12px;
            padding: 48px 64px;
            max-width: 600px;
            width: 100%;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        h1 {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 24px;
            color: #1a1a1a;
        }
        p {
            font-size: 18px;
            line-height: 1.6;
            color: #333;
            margin-bottom: 16px;
        }
        p:last-child {
            margin-bottom: 0;
        }
    </style>
</head>
<body>
    <div class="error-card">
        <h1>{{.Title}}</h1>
        <p>{{.Message}}</p>
        <p>Please contact the system administrator for assistance.</p>
    </div>
</body>
</html>`
