from django import template

register = template.Library()

@register.filter
def user_type_color(user_type):
    color_map = {
        'athlete': 'blue',
        'coach': 'purple',
        'psychologist': 'indigo',
        'nutritionist': 'teal',
        'admin': 'red'
    }
    return color_map.get(user_type, 'gray')