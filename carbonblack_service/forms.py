from django import forms

class CarbonBlackInegrationConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    cb_server_url = forms.CharField(required=True,
                                    label='Carbon Black Server Address',
                                    help_text='URL for Carbon Black Server',
                                    widget=forms.TextInput(),
                                    initial='')

    cb_api_token = forms.CharField(required=True,
                                    label='Carbon Black API Token',
                                    help_text='API Token for a Carbon Black User',
                                    widget=forms.TextInput(),
                                    initial='')


    cb_max_wait_time = forms.IntegerField(required=False,
                                label="Carbon Black Poll Time",
                                initial=900,
                                help_text="The length of time in seconds to poll the Carbon Black server")

    cb_initial_wait_time = forms.IntegerField(required=False,
                                label="Carbon Black Initial Delay Time",
                                initial=0,
                                help_text="The length of time in seconds before the service starts to poll the Carbon Black server")

    #cb_crits_user = forms.CharField(required=True,
    #                                label='Crits User To Add Samples from Carbon Black',
    #                                help_text='A user to add data from Carbon Black service',
    #                                widget=forms.TextInput(),
    #                                initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(CarbonBlackInegrationConfigForm, self).__init__(*args, **kwargs)
