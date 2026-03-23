## 2024-05-20 - Missing Form Label Associations in Config Template
**Learning:** The application's `config.html` form template has a pattern of omitting explicit `id` attributes on inputs and omitting `for` attributes on their adjacent `<label>` elements, breaking screen reader association and decreasing click targets for users.
**Action:** When working with form templates in this application, always verify that `id` and `for` attributes are explicitly defined and correctly associated, especially inside loop structures like `range`.
