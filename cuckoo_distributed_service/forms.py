from django import forms

class CuckooDistributedConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    rabbit_address = forms.CharField(required=True,
                          label="RabbitMQ URL",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="URL for the RabbitMQ Server, example: "
                                    "10.0.0.1")
    rabbit_port = forms.CharField(required=True,
                          label="RabbitMQ Port",
                          widget=forms.TextInput(),
                          initial='5672',
                          help_text="Port for the RabbitMQ Server, example: "
                                    "5672")
    rabbit_user = forms.CharField(required=True,
                          label="RabbitMQ User",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="User for the RabbitMQ Server, example: "
                                    "username")
    rabbit_pw = forms.CharField(required=True,
                          label="RabbitMQ Password",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="Password for the RabbitMQ Server, example: "
                                    "password")
    rabbit_key = forms.CharField(required=True,
                          label="RabbitMQ routing key",
                          widget=forms.TextInput(),
                          initial='worker/feed_cuckoo',
                          help_text="Route Key for the RabbitMQ Server, example: "
                                    "worker/feed_cuckoo")
    rabbit_exchange = forms.CharField(required=False,
                          label="RabbitMQ exchange",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="Exchange for the RabbitMQ Server, leave empty for none")
    crits_api_key = forms.CharField(required=True,
                          label="CRITS api key",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="The CRITS api key of the executing user.")
  
    def __init__(self, *args, **kwargs):
        super(CuckooDistributedConfigForm, self).__init__(*args, **kwargs)
