
$(document).ready(function() {
    const urlParams = new URLSearchParams(window.location.search);
    const templateId = urlParams.get('templateId');

    if (templateId) {
        loadTemplateContent(templateId); // Load specific template content using its ID
    }
});
